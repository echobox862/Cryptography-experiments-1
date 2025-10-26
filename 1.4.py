import hashlib
import itertools
import time

# 目标SHA1哈希值（需破解的密码对应的哈希）
TARGET_SHA1_HASH = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# 密码每位的可选字符集（共8位，每位对应2个可选字符）
POSITION_CHAR_OPTIONS = [
    ['Q', 'q'],  # 第1位可选字符
    ['W', 'w'],  # 第2位可选字符
    ['5', '%'],  # 第3位可选字符
    ['8', '('],  # 第4位可选字符
    ['=', '0'],  # 第5位可选字符
    ['I', 'i'],  # 第6位可选字符
    ['*', '+'],  # 第7位可选字符
    ['n', 'N']   # 第8位可选字符
]


def calculate_sha1_hash(input_str):
    """
    计算输入字符串的SHA1哈希值，返回小写十六进制结果
    
    参数:
        input_str: 待计算哈希的字符串
        
    返回:
        str: 输入字符串的SHA1哈希值（40位小写十六进制字符串）
    """
    # 创建SHA1哈希对象，对字符串编码后进行哈希计算
    sha1_obj = hashlib.sha1(input_str.encode())
    # 获取哈希结果的十六进制字符串
    hash_result = sha1_obj.hexdigest()
    return hash_result


def brute_force_sha1_password():
    """
    暴力破解SHA1哈希对应的密码：
    1. 生成密码每位字符的所有组合（基于POSITION_CHAR_OPTIONS）
    2. 对每个组合进行全排列，生成候选密码
    3. 计算候选密码的SHA1哈希，与目标哈希比对
    4. 找到匹配密码后输出结果及耗时，立即退出程序
    """
    # 记录破解开始时间
    start_time = time.time()
    
    # 生成8位密码的所有字符组合（替代原8层嵌套循环）
    # itertools.product生成各位置字符的笛卡尔积，每个结果是8个字符的元组
    for char_combination in itertools.product(*POSITION_CHAR_OPTIONS):
        # 将字符元组拼接为完整字符串（如('Q','W','5',...,'n') → "QW5...n"）
        base_password = "".join(char_combination)
        
        # 对当前字符组合进行全排列，生成所有可能的密码顺序
        for password_perm in itertools.permutations(base_password, 8):
            # 将排列结果拼接为候选密码
            candidate_password = "".join(password_perm)
            
            # 计算候选密码的SHA1哈希
            candidate_hash = calculate_sha1_hash(candidate_password)
            
            # 比对哈希值，若匹配则输出结果并退出
            if candidate_hash == TARGET_SHA1_HASH:
                print(f"找到匹配密码: {candidate_password}")
                # 计算并输出破解耗时
                end_time = time.time()
                print(f"破解耗时: {end_time - start_time:.6f}s")
                # 找到密码后立即退出程序
                exit(0)


# 主程序入口
if __name__ == "__main__":
    brute_force_sha1_password()