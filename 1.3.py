import base64
import itertools

# 英文文本字母及空格的频率表（用于可信度评分）
LETTER_FREQUENCY = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339,
    'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
    'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094,
    'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302,
    'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
    's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


def calculate_text_score(byte_array):
    """
    根据字母频率表计算文本的可信度评分（得分越高越可能是英文文本）
    
    参数:
        byte_array: 待评分的字节数组（bytes类型）
    
    返回:
        float: 文本的频率评分，累加每个字符的频率值
    """
    score = 0.0
    for byte in byte_array:
        # 转换为小写字符后查频率表，非表中字符得0分
        score += LETTER_FREQUENCY.get(chr(byte).lower(), 0.0)
    return score


def xor_with_single_char(byte_array, key_byte):
    """
    用单字节密钥对字节数组进行异或运算
    
    参数:
        byte_array: 待加密/解密的字节数组（bytes类型）
        key_byte: 单字节密钥（0-255的整数）
    
    返回:
        bytes: 异或运算后的结果字节数组
    """
    result = b''
    for byte in byte_array:
        result += bytes([byte ^ key_byte])
    return result


def brute_force_single_char_xor(ciphertext):
    """
    爆破单字节XOR加密的密文，找到最可能的明文和密钥
    
    参数:
        ciphertext: 单字节XOR加密的密文（bytes类型）
    
    返回:
        dict: 包含最佳密钥、评分和明文的字典，格式为
              {'key': 密钥字节, 'score': 评分, 'plaintext': 明文字节数组}
    """
    results = []
    # 枚举所有可能的单字节密钥（0-255）
    for key in range(256):
        plaintext = xor_with_single_char(ciphertext, key)
        score = calculate_text_score(plaintext)
        results.append({
            'key': key,
            'score': score,
            'plaintext': plaintext
        })
    # 按评分降序排序，返回最佳结果
    return sorted(results, key=lambda x: x['score'], reverse=True)[0]


def xor_with_repeating_key(byte_array, key):
    """
    用重复的密钥对字节数组进行异或运算（密钥循环使用）
    
    参数:
        byte_array: 待加密/解密的字节数组（bytes类型）
        key: 密钥字节数组（bytes类型）
    
    返回:
        bytes: 异或运算后的结果字节数组
    """
    result = b''
    key_length = len(key)
    for i, byte in enumerate(byte_array):
        # 密钥循环索引：i % 密钥长度
        result += bytes([byte ^ key[i % key_length]])
    return result


def compute_hamming_distance(bytes1, bytes2):
    """
    计算两个等长字节数组的汉明距离（不同位的数量）
    
    参数:
        bytes1: 第一个字节数组（bytes类型）
        bytes2: 第二个字节数组（bytes类型）
    
    返回:
        int: 汉明距离（两个字节数组中不同位的总数）
    
    异常:
        AssertionError: 若两个字节数组长度不同则触发
    """
    assert len(bytes1) == len(bytes2), "两个字节数组必须等长"
    distance = 0
    for b1, b2 in zip(bytes1, bytes2):
        # 异或结果的二进制中1的数量即为不同位的数量
        xor_result = b1 ^ b2
        distance += bin(xor_result).count('1')
    return distance


def break_repeating_key_xor(ciphertext):
    """
    破解重复密钥XOR加密的密文，找到最可能的明文和密钥
    
    参数:
        ciphertext: 重复密钥XOR加密的密文（bytes类型）
    
    返回:
        tuple: 包含最佳明文和密钥的元组，格式为(明文字节数组, 密钥字节数组)
    """
    # 步骤1：计算不同密钥长度的归一化汉明距离，筛选最佳候选长度
    key_size_distances = {}
    # 尝试可能的密钥长度（2到40）
    for key_size in range(2, 41):
        # 取前4个长度为key_size的块
        chunks = [ciphertext[i:i + key_size] for i in range(0, len(ciphertext), key_size)][:4]
        total_distance = 0
        # 计算所有块对之间的汉明距离总和
        for chunk1, chunk2 in itertools.combinations(chunks, 2):
            total_distance += compute_hamming_distance(chunk1, chunk2)
        # 计算平均距离并归一化（除以密钥长度）
        avg_distance = total_distance / 6  # 4个块有6对组合
        normalized_distance = avg_distance / key_size
        key_size_distances[key_size] = normalized_distance
    
    # 取距离最小的前3个密钥长度作为候选
    best_key_sizes = sorted(key_size_distances, key=key_size_distances.get)[:3]
    print(f"候选密钥长度: {best_key_sizes}")

    # 步骤2：对每个候选密钥长度，破解密钥并解密
    decrypted_candidates = []
    for key_size in best_key_sizes:
        key = b''
        # 按密钥长度分组，每组用单字节爆破破解
        for i in range(key_size):
            # 提取第i组：从索引i开始，每隔key_size取一个字节
            group = b''.join([bytes([ciphertext[j]]) for j in range(i, len(ciphertext), key_size)])
            # 爆破该组的单字节密钥
            best_group_key = brute_force_single_char_xor(group)['key']
            key += bytes([best_group_key])
        # 用得到的密钥解密整个密文
        decrypted = xor_with_repeating_key(ciphertext, key)
        decrypted_candidates.append((decrypted, key))
    
    # 步骤3：选择评分最高的解密结果作为最终答案
    return max(decrypted_candidates, key=lambda x: calculate_text_score(x[0]))


# 主程序：读取密文并解密
if __name__ == "__main__":
    # 读取base64编码的密文并解码
    with open("ciphertext.txt", "r") as file:
        encoded_data = file.read().strip()
    ciphertext = base64.b64decode(encoded_data)
    
    # 破解重复密钥XOR加密
    plaintext, key = break_repeating_key_xor(ciphertext)
    
    # 输出结果
    print(f"密钥: {key.decode()}")
    print(f"密钥长度: {len(key)}")
    print("解密明文:")
    print(plaintext.decode().rstrip())