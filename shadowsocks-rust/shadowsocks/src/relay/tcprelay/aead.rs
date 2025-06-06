//aead.rs
//! AEAD 数据包 I/O 功能
//!
//! AEAD 协议说明参考 <https://shadowsocks.org/en/spec/AEAD.html>。
//!
//! plain
//! TCP 请求（加密前）
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP 请求（加密后，*ciphertext*）
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk（加密前）
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk（加密后，*ciphertext*）
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//!
use std::{
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{self, Poll},
    u16,
};

use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use log::trace;
use rand::seq::SliceRandom;
use rand::Rng;
use rand_pcg::Pcg64;
use rand_seeder::Seeder;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    context::Context,
    crypto::{v1::Cipher, CipherKind},
};

/// AEAD 数据包最大大小应小于 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

/// 由于可能会在负载中添加额外字节，这里定义最大合理负载大小为 0x2F00
pub const MAX_PAYLOAD_SIZE: usize = 0x2F00;
// 新增辅助函数用于打印十六进制数据

fn print_hex_data(data: &[u8], title: &str) {
    println!("\n=== {} ===", title);

    // Calculate dynamic widths based on the data
    let bytes_per_row = 32; // Can be adjusted if needed
    let hex_width = bytes_per_row * 3 - 1; // Each byte takes 2 chars + 1 space, minus trailing space
    let utf8_width = bytes_per_row;
    let pos_width = 4; // For showing position up to 9990

    // Helper function to create horizontal line
    let make_horizontal_line = |ch1: char, ch2: char, ch3: char, ch4: char| {
        format!(
            "{}{}{}{}{}{}{}",
            ch1,
            "─".repeat(pos_width),
            ch2,
            "─".repeat(hex_width),
            ch3,
            "─".repeat(utf8_width),
            ch4
        )
    };

    // Print table header
    println!("{}", make_horizontal_line('┌', '┬', '┬', '┐'));
    println!("│{:^pos_width$}│{:^hex_width$}│{:^utf8_width$}│",
             "Pos", "Hexadecimal", "UTF-8",
             pos_width = pos_width,
             hex_width = hex_width,
             utf8_width = utf8_width
    );
    println!("{}", make_horizontal_line('├', '┼', '┼', '┤'));

    // Print data rows
    for (i, chunk) in data.chunks(bytes_per_row).enumerate() {
        let hex_str = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ");

        let utf8_str = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect::<String>();

        println!("│{:>3}0│{:<hex_width$}│{:<utf8_width$}│",
                 i,
                 hex_str,
                 utf8_str,
                 hex_width = hex_width,
                 utf8_width = utf8_width
        );
    }

    // Print table footer
    println!("{}", make_horizontal_line('└', '┴', '┴', '┘'));
}
/// AEAD 协议中可能出现的错误类��
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("header 太短，期望 {0} 字节，但实际只有 {1} 字节")]
    HeaderTooShort(usize, usize),
    #[error("解密数据失败")]
    DecryptDataError,
    #[error("解密长度失败")]
    DecryptLengthError,
    #[error("数据包过大（{0:#x}），AEAD 规范要求必须小于 0x3FFF，最高两位必须为 0")]
    DataTooLong(usize),
}

/// AEAD 协议返回值类型
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> io::Error {
        match e {
            ProtocolError::IoError(err) => err,
            _ => io::Error::new(ErrorKind::Other, e),
        }
    }
}

/// 记录解密过程中的读取状态
enum DecryptReadState {
    /// 等待从流中读取盐（salt）
    WaitSalt { key: Bytes },
    /// 读取 length 字段，并解密长度
    ReadLength,
    /// 读取并解密真正数据
    ReadData { length: usize },
    /// 将解密后的缓冲区写入给定的用户缓冲区
    BufferedData { pos: usize },
}

/// 自动解密的 Reader 封装
pub struct DecryptedReader {
    state: DecryptReadState,
    /// 专门用于解密 length 字段的 Cipher
    cipher_for_length: Option<Cipher>,
    /// 专门用于解密真实数据的 Cipher
    cipher_for_data: Option<Cipher>,
    buffer: BytesMut,
    method: CipherKind,
    salt: Option<Bytes>,
    has_handshaked: bool,
    /// 用户提供的密钥
    key: Vec<u8>,
    /// 是否是第一个数据包
    is_first_packet: bool,
}

impl DecryptedReader {
    /// 根据加密方法和 key 新建 DecryptedReader
    pub fn new(method: CipherKind, key: &[u8]) -> DecryptedReader {
        if method.salt_len() > 0 {
            DecryptedReader {
                state: DecryptReadState::WaitSalt {
                    key: Bytes::copy_from_slice(key),
                },
                cipher_for_length: None,
                cipher_for_data: None,
                buffer: BytesMut::with_capacity(method.salt_len()),
                method,
                salt: None,
                has_handshaked: false,
                key: key.to_vec(),
                is_first_packet: true,
            }
        } else {
            // 如果算法不需要 salt，则直接将状态置为 ReadLength
            DecryptedReader {
                state: DecryptReadState::ReadLength,
                cipher_for_length: Some(Cipher::new(method, key, &[])),
                cipher_for_data: Some(Cipher::new(method, key, &[])),
                buffer: BytesMut::with_capacity(2 + method.tag_len()),
                method,
                salt: None,
                has_handshaked: false,
                key: key.to_vec(),
                is_first_packet: true,
            }
        }
    }

    /// 返回当前 salt
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    /// 异步读取并解密数据，写入用户提供的 read buffer
    pub fn poll_read_decrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                // 先等待读取盐，然后初始化 Cipher
                DecryptReadState::WaitSalt { ref key } => {
                    let key = unsafe { &*(key.as_ref() as *const _) };
                    ready!(self.poll_read_salt(cx, stream, key))?;

                    // 设置读 length 状态
                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                    self.has_handshaked = true;
                }
                // 读取并解密 length
                DecryptReadState::ReadLength => match ready!(self.poll_read_length(cx, stream))? {
                    None => {
                        // 如果返回 None，表示已经读到 EOF
                        return Ok(()).into();
                    }
                    Some(length) => {
                        self.buffer.clear();
                        self.state = DecryptReadState::ReadData { length };
                        self.buffer.reserve(length);
                    }
                },
                // 读取并解密真正的数据
                DecryptReadState::ReadData { length } => {
                    ready!(self.poll_read_data(cx, context, stream, length))?;
                    self.state = DecryptReadState::BufferedData { pos: 0 };
                }
                // 把解密完成后的缓冲数据复制到用户提供的 read buffer
                DecryptReadState::BufferedData { ref mut pos } => {
                    if *pos < self.buffer.len() {
                        let buffered = &self.buffer[*pos..];

                        let consumed = usize::min(buffered.len(), buf.remaining());
                        buf.put_slice(&buffered[..consumed]);

                        *pos += consumed;

                        return Ok(()).into();
                    }
                    // 如果全部拷贝完毕，重新去读下一个 length
                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                }
            }
        }
    }

    /// 等待从流里读取 salt
    fn poll_read_salt<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, key: &[u8]) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let salt_len = self.method.salt_len();

        let n = ready!(self.poll_read_exact(cx, stream, salt_len))?;
        if n < salt_len {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        let salt = &self.buffer[..salt_len];
        // print_hex_data(salt, "Salt"); // 打印 salt
        self.salt = Some(Bytes::copy_from_slice(salt));

        trace!("读取到 AEAD salt = {:?}", ByteStr::new(salt));

        // 同时生成两个 Cipher：一个用于 length 的解密，一个用于数据内容的解密
        let cipher_for_length = Cipher::new(self.method, key, salt);
        let cipher_for_data = Cipher::new(self.method, key, salt);

        self.cipher_for_length = Some(cipher_for_length);
        self.cipher_for_data = Some(cipher_for_data);

        Ok(()).into()
    }

    /// 读取并解密 length
    fn poll_read_length<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
    ) -> Poll<ProtocolResult<Option<usize>>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let length_len = 2 + self.method.tag_len();

        let n = ready!(self.poll_read_exact(cx, stream, length_len))?;
        if n == 0 {
            // 如果直接返回 0，表示 EOF
            return Ok(None).into();
        }
        // print_hex_data(&self.buffer[..length_len], "Encrypted Length"); // 打印加密的长度

        let cipher = self.cipher_for_length.as_mut().expect("cipher_for_length 未初始化");
        let m = &mut self.buffer[..length_len];

        let length = DecryptedReader::decrypt_length(cipher, m)?;
        println!("解密: 填充的长度为:{}",length);
        Ok(Some(length)).into()
    }

    /// 读取并解密真正的数据
    fn poll_read_data<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        size: usize,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let n = ready!(self.poll_read_exact(cx, stream, size))?;
        if n == 0 {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }
        // print_hex_data(&self.buffer[..size], "Encrypted Data"); // 打印加密数据

        // 如果是第一次数据包，需要做特殊的比特级别解码
        // print_hex_data(&self.buffer[..size], "First Packet Before Bit Manipulation");

        if self.is_first_packet {
            trace!("第一次数据包，需要进行比特级别还原，当前字节数 size = {}", size);

            let bit_vector_len = size * 8;

            // 构造随机数生成器，key 用于种子
            let mut rng: Pcg64 = Seeder::from(&self.key).make_rng();
            let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
            shuffled_idx.shuffle(&mut rng);

            // 将字节流展开为比特流
            let mut bit_vector: Vec<u8> = Vec::with_capacity(bit_vector_len);
            for i in 0..size {
                for j in 0..8 {
                    let bit = (self.buffer[i] >> j) & 1;
                    bit_vector.push(bit);
                }
            }

            // 反向 unshuffle
            let mut bit_vector_unshuffled = vec![0u8; bit_vector_len];
            for i in 0..bit_vector_len {
                bit_vector_unshuffled[i] = bit_vector[shuffled_idx[i]];
            }

            // 将解开的比特流重新组合成字节流
            let mut decoded_data: Vec<u8> = Vec::with_capacity(size);
            for i in 0..size {
                let mut byte: u8 = 0;
                for j in 0..8 {
                    byte |= bit_vector_unshuffled[i * 8 + j] << j;
                }
                decoded_data.push(byte);
            }

            // 读取末尾 4 字节以确定真实的多余字节长度
            let mut extra_bytes_len: u32 = 0;
            for i in 0..4 {
                extra_bytes_len |= (decoded_data[size - i - 1] as u32) << (i * 8);
            }
            // let buffer_len = decoded_data.len();

            let mut number_of_ones: u32 = 0;
            let mut number_of_zeros: u32 = 0;
            // 1) 先算一算 salt、length 字段本身（2 字节）以及它的 AEAD tag 的字节数
            let salt_bytes      = self.method.salt_len();                       // salt 本身的字节数
            let length_tag_bytes = self.cipher_for_length
                .as_ref()
                .expect("cipher_for_length must be initialized")
                .tag_len();                                                    // length 字段的 tag 长度
            let header_bytes     = salt_bytes + 2 /*length plaintext*/ + length_tag_bytes;

            // 2) 把它们的比特数平均加到 ones/zeros 上（是假设 random 分布）
            let header_bits = (header_bytes * 8) as u32;
            number_of_ones  += header_bits;
            number_of_zeros += header_bits;

            // 3) 得到最终比率
            let current_ratio = if number_of_zeros == 0 {
                f32::INFINITY
            } else {
                number_of_ones as f32 / number_of_zeros as f32
            };

            trace!("解密: 当前(1/0)比率 = {}", current_ratio);
            println!("解密: 当前(1/0)比率 = {:.4}", current_ratio);
            // 在 truncate 之前，size 此时等于 decoded_data.len()
            // let payload_len = size - extra_bytes_len as usize - 4;
            // if extra_bytes_len > 0 {
            //     // padding 区域从 payload_len .. payload_len+extra_bytes_len
            //     let pad_byte = decoded_data[payload_len];
            //     // 判断填充的是 0 还是 1
            //     let bit_value = if pad_byte == 0 { 0 } else { 1 };
            //     // 统计字节级比率
            //     let total_bytes = payload_len + extra_bytes_len as usize;
            //     let byte_ratio = extra_bytes_len as f64 / total_bytes as f64 * 100.0;
            //     // 统计比特级比率（其实和字节比率一样）
            //     let total_bits = total_bytes * 8;
            //     let pad_bits = extra_bytes_len as usize * 8;
            //     let bit_ratio = pad_bits as f64 / total_bits as f64 * 100.0;
            //
            //     println!(
            //         "多余的是 {}，填充字节数 = {} / {}（{:.2}%），填充比特数 = {} / {}（{:.2}%）",
            //         bit_value,
            //         extra_bytes_len,
            //         total_bytes,
            //         byte_ratio,
            //         pad_bits,
            //         total_bits,
            //         bit_ratio
            //     );
            // } else {
            //     println!("没有多余填充");
            // }

            // 截断这部分多余的数据 + 4 字节记录
            decoded_data.truncate(size - extra_bytes_len as usize - 4);

            // print_hex_data(&decoded_data, "First Packet After Bit Manipulation");


            // 替换原有 buffer
            self.buffer.clear();
            self.buffer.put_slice(&decoded_data);

            self.is_first_packet = false;
        }

        // 去掉 tag 部分，获取加密前实际的数据长度
        let data_len = self.buffer.len() - self.method.tag_len();

        let cipher = self.cipher_for_data.as_mut().expect("cipher_for_data 未初始化");

        let m = &mut self.buffer[..];
        if !cipher.decrypt_packet(m) {
            return Err(ProtocolError::DecryptDataError).into();
        }
        // print_hex_data(&self.buffer[..data_len], "Decrypted Data"); // 打印解密后的数据

        // 如果之前成功解密，就需要检查 salt 是否重复（重放攻击）
        if let Some(ref salt) = self.salt {
            context.check_nonce_replay(self.method, salt)?;
        }

        // 去除 tag
        self.buffer.truncate(data_len);

        Ok(()).into()
    }

    /// poll_read_exact，保证恰好读取指定字节数
    fn poll_read_exact<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, size: usize) -> Poll<io::Result<usize>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        assert!(size != 0);

        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            let buffer = &mut self.buffer.chunk_mut()[..remaining];

            let mut read_buf =
                ReadBuf::uninit(unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut _, remaining) });
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut read_buf))?;

            let n = read_buf.filled().len();
            if n == 0 {
                if !self.buffer.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                } else {
                    return Ok(0).into();
                }
            }

            unsafe {
                self.buffer.advance_mut(n);
            }
        }

        Ok(size).into()
    }

    /// 解密长度字段
    fn decrypt_length(cipher: &mut Cipher, m: &mut [u8]) -> ProtocolResult<usize> {
        if !cipher.decrypt_packet(m) {
            return Err(ProtocolError::DecryptLengthError);
        }
        let plen = u16::from_be_bytes([m[0], m[1]]) as usize;

        if plen > MAX_PACKET_SIZE {
            return Err(ProtocolError::DataTooLong(plen));
        }

        Ok(plen)
    }

    /// 判断是否已完成握手
    pub fn handshaked(&self) -> bool {
        self.has_handshaked
    }
}

/// 写入过程的不同阶段
enum EncryptWriteState {
    /// 组装和加密数据包
    AssemblePacket,
    /// 将已经加密好的数据写出去
    Writing { pos: usize },
}

/// 自动加密的 Writer 封装
pub struct EncryptedWriter {
    /// 专门用于加密 length 字段的 Cipher
    cipher_for_length: Cipher,
    /// 专门用于加密真实数据的 Cipher
    cipher_for_data: Cipher,
    /// 内部缓冲区
    buffer: BytesMut,
    /// 当前写入过程的状态
    state: EncryptWriteState,
    /// 发送给对端的盐（nonce）
    salt: Bytes,
    /// 用户提供的密钥，用于后续比特级别打乱
    key: Vec<u8>,
    /// 标记是否是第一包数据，需要比特级别打乱
    is_first_packet: bool,
}

impl EncryptedWriter {
    /// 根据加密方法、key 和 nonce 创建一个新的 EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        // 首次发送时要先写入 nonce
        let mut buffer = BytesMut::with_capacity(nonce.len());
        buffer.put(nonce);

        EncryptedWriter {
            cipher_for_length: Cipher::new(method, key, nonce),
            cipher_for_data: Cipher::new(method, key, nonce),
            buffer,
            state: EncryptWriteState::AssemblePacket,
            salt: Bytes::copy_from_slice(nonce),
            key: key.to_vec(),
            is_first_packet: true,
        }
    }

    /// 返回盐（nonce）
    pub fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    /// 异步写入并加密用户提供的数据
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        // 限制最大可写入长度，防止 payload 过大
        if buf.len() > MAX_PAYLOAD_SIZE {
            buf = &buf[..MAX_PAYLOAD_SIZE];
        }

        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    // 1) 先对数据本体进行加密
                    let data_size = buf.len() + self.cipher_for_data.tag_len();
                    let mut buffer_data = BytesMut::with_capacity(data_size);

                    let mbuf = buffer_data.chunk_mut();
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    buffer_data.put_slice(buf);
                    self.cipher_for_data.encrypt_packet(mbuf);
                    unsafe { buffer_data.advance_mut(self.cipher_for_data.tag_len()) };

                    // 如果是第一包，要对数据进行比特级别的混淆
                    if self.is_first_packet {
                        trace!("第一包数据，开始进行比特级别混淆，原始加密后长度 = {}", buffer_data.len());
                        let buffer_len = buffer_data.len();

                        // 统计比特流中 1 和 0 的数量
                        let mut number_of_ones: u32 = 0;
                        let mut number_of_zeros: u32 = 0;
                        for i in 0..buffer_len {
                            for j in 0..8 {
                                let bit = (buffer_data[i] >> j) & 1;
                                if bit == 1 {
                                    number_of_ones += 1;
                                } else {
                                    number_of_zeros += 1;
                                }
                            }
                        }
                        trace!(
                            "初始统计：1 的数量 = {}, 0 的数量 = {}",
                            number_of_ones,
                            number_of_zeros
                        );

                        // 加上 salt + length + tag 的比特总量
                        number_of_ones += ((self.salt.len() + self.cipher_for_length.tag_len() + 2) * 8) as u32;
                        number_of_zeros += ((self.salt.len() + self.cipher_for_length.tag_len() + 2) * 8) as u32;

                        let current_ratio = number_of_ones as f32 / number_of_zeros as f32;
                        trace!("当前(1/0)比率 = {}", current_ratio);
                        println!("当前(1/0)比率 = {}", current_ratio);
                        let mut rng = rand::thread_rng();
                        let mut extra_bytes_len = 0u32;

                        // 根据随机目标区间向数据尾部添加额外的 0 或 1，以调整比特占比
                        if current_ratio > 0.7 && current_ratio < 1.4 {
                            if number_of_ones <= number_of_zeros {
                                // 添加更多 0
                                let target_ratio = rng.gen_range(0.6..0.7);
                                trace!("加密: 目标(1/0)比率 = {}", target_ratio);
                                println!("加密: 目标(1/0)比率 = {}", target_ratio);
                                extra_bytes_len =
                                    ((number_of_ones as f32 / target_ratio) as u32 - number_of_zeros) / 8 + 1;
                                buffer_data.reserve(extra_bytes_len as usize + 4);
                                for _ in 0..extra_bytes_len {
                                    buffer_data.put_u8(0);
                                }
                            } else {
                                // 添加更多 1（0xFF）
                                let target_ratio = rng.gen_range(1.4..1.5);
                                trace!("加密: 目标(1/0)比率 = {}", target_ratio);
                                println!("加密: 目标(1/0)比率 = {}", target_ratio);
                                extra_bytes_len =
                                    ((number_of_zeros as f32 * target_ratio) as u32 - number_of_ones) / 8 + 1;
                                buffer_data.reserve(extra_bytes_len as usize + 4);
                                for _ in 0..extra_bytes_len {
                                    buffer_data.put_u8(0xFF);
                                }
                            }
                        }
                        trace!("额外添加字节数 = {}", extra_bytes_len);
                        println!("加密: 额外添加字节数 = {}", extra_bytes_len);
                        // 在末尾记录这个额外字节长度
                        buffer_data.put_u32(extra_bytes_len);

                        // 进行比特级别 shuffle
                        let encoded_data_size = buffer_data.len();
                        let bit_vector_len = encoded_data_size * 8;

                        let mut rng: Pcg64 = Seeder::from(&self.key).make_rng();
                        let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
                        shuffled_idx.shuffle(&mut rng);

                        let mut bit_vector: Vec<u8> = Vec::with_capacity(bit_vector_len);
                        for i in 0..encoded_data_size {
                            for j in 0..8 {
                                let bit = (buffer_data[i] >> j) & 1;
                                bit_vector.push(bit);
                            }
                        }

                        let mut bit_vector_shuffled = vec![0u8; bit_vector_len];
                        for i in 0..bit_vector_len {
                            bit_vector_shuffled[shuffled_idx[i]] = bit_vector[i];
                        }

                        let mut encoded_data_shuffled: Vec<u8> = Vec::with_capacity(encoded_data_size);
                        for i in 0..encoded_data_size {
                            let mut byte: u8 = 0;
                            for j in 0..8 {
                                byte |= bit_vector_shuffled[i * 8 + j] << j;
                            }
                            encoded_data_shuffled.push(byte);
                        }

                        buffer_data.clear();
                        buffer_data.put_slice(&encoded_data_shuffled);

                        self.is_first_packet = false;
                    }

                    // 2) 加密 length 字段 (2 + tag_len)
                    let length_size = 2 + self.cipher_for_length.tag_len();
                    self.buffer.reserve(length_size);

                    let mbuf = &mut self.buffer.chunk_mut()[..length_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    self.buffer.put_u16(buffer_data.len() as u16);
                    self.cipher_for_length.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher_for_length.tag_len()) };

                    // 3) 将加密后的数据本体放到 buffer
                    self.buffer.put_slice(&buffer_data);

                    // 4) 进入写状态
                    self.state = EncryptWriteState::Writing { pos: 0 };
                }
                EncryptWriteState::Writing { ref mut pos } => {
                    while *pos < self.buffer.len() {
                        let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.buffer[*pos..]))?;
                        if n == 0 {
                            return Err(ErrorKind::UnexpectedEof.into()).into();
                        }
                        *pos += n;
                    }

                    // 写完后，回到组装阶段，并清空缓冲
                    self.state = EncryptWriteState::AssemblePacket;
                    self.buffer.clear();

                    return Ok(buf.len()).into();
                }
            }
        }
    }
}