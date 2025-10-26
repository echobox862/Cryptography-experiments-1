import string

def hex_to_byte_list(hex_text):
    """
    将十六进制字符串转换为十进制字节列表（每个元素对应一个十六进制对的十进制值）
    
    参数:
        hex_text: 待转换的十六进制字符串（无空格连续形式）
    
    返回:
        list: 十进制字节组成的列表，每个元素范围0-255
    """
    byte_list = []
    # 每两个字符为一组解析为十六进制值，转换为十进制后存入列表
    for i in range(0, len(hex_text), 2):
        hex_pair = hex_text[i:i+2]  # 提取十六进制对（如"F9"）
        byte_list.append(int(hex_pair, 16))  # 转换为十进制整数
    return byte_list

def get_valid_keys(byte_group):
    """
    针对字节分组，筛选出所有可能的合法密钥（密钥与字节异或后结果为合法字符）
    
    参数:
        byte_group: 按密钥位置分组的字节列表（如密钥长度为3时，第0组为[0,3,6,...]位置的字节）
    
    返回:
        list: 合法密钥的十进制列表，每个密钥满足：对分组中所有字节，密钥^字节的结果为合法字符
    """
    # 定义合法字符集：大小写字母、逗号、句号、空格
    valid_chars = set(string.ascii_letters + ',.' + ' ')
    valid_keys = []
    
    # 枚举所有可能的密钥（0-255，十六进制0x00到0xFF）
    for key in range(0x00, 0xFF + 1):
        is_valid = True
        # 检查当前密钥对分组中所有字节的解密结果是否合法
        for byte in byte_group:
            decrypted_char = chr(key ^ byte)  # 异或解密得到字符
            if decrypted_char not in valid_chars:
                is_valid = False
                break
        if is_valid:
            valid_keys.append(key)
    return valid_keys

# 待解密的十六进制密文
ciphertext = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A\
7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A\
70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A\
76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE\
70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D96\
3FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC8\
7EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D4\
7AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D9\
3FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A\
7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF\
3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D4\
69F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF\
67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED8\
7AB1D021A255DF71B1C436BF479A7AF0C13AA14794'

# 步骤1：将密文转换为十进制字节列表
cipher_bytes = hex_to_byte_list(ciphertext)

# 步骤2：枚举可能的密钥长度（1到13），确定实际密钥长度和每组可能的密钥
key_length = 0  # 实际密钥长度
key_candidates = []  # 存储每个位置的可能密钥（二维列表：[位置0的可能密钥, 位置1的可能密钥, ...]）

# 枚举密钥长度（1到13，因为range(1,14)生成1-13的整数）
for length in range(1, 14):
    group_keys = []  # 存储当前长度下，每个分组的可能密钥
    # 对每个分组位置（0到length-1）提取字节组并计算可能的密钥
    for index in range(length):
        # 提取分组：从index开始，每隔length取一个字节（如length=3时，index=0的分组为[0,3,6,...]）
        byte_group = cipher_bytes[index::length]
        # 获取该分组的合法密钥
        valid_keys = get_valid_keys(byte_group)
        # 若当前分组无合法密钥，说明该长度不可能是密钥长度，中断循环
        if not valid_keys:
            break
        group_keys.append(valid_keys)
    # 若所有分组都有合法密钥，说明找到可能的密钥长度
    if group_keys:
        key_length = length
        key_candidates = group_keys
        print(f"密钥长度: {length}")
        print(f"各位置可能的密钥: {key_candidates}")

# 步骤3：使用确定的密钥解密（取每个位置的第一个可能密钥）
decrypted_text = ""
for i in range(len(cipher_bytes)):
    # 计算当前字节对应的密钥位置（循环取模）
    key_pos = i % key_length
    # 取该位置的第一个可能密钥进行异或解密
    key = key_candidates[key_pos][0]
    decrypted_char = chr(cipher_bytes[i] ^ key)
    decrypted_text += decrypted_char

# 输出解密后的明文
print("解密结果:")
print(decrypted_text)