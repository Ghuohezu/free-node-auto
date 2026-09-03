#!/usr/bin/env python3
"""
测试脚本 - 验证 clean_nodes.py 的修复是否有效
"""
import os
import sys
import asyncio

# 添加脚本目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_clean_nodes():
    """测试 clean_nodes 脚本"""
    print("\n" + "="*70)
    print("🧪 开始测试节点清洗脚本")
    print("="*70 + "\n")
    
    # 导入修复后的脚本
    try:
        from clean_nodes import main
        print("✅ 成功导入 clean_nodes 模块\n")
    except Exception as e:
        print(f"❌ 导入失败: {e}\n")
        return False
    
    # 运行主程序
    try:
        await main()
        print("\n✅ 脚本执行成功，无异常！\n")
        return True
    except Exception as e:
        print(f"\n❌ 脚本执行失败: {e}\n")
        import traceback
        traceback.print_exc()
        return False

def verify_output_files():
    """验证输出文件"""
    print("="*70)
    print("📋 验证输出文件")
    print("="*70 + "\n")
    
    files_to_check = [
        ("output/nodes.txt", "清洗后的节点"),
        ("output/result.json", "JSON 结果"),
        ("output/report.html", "HTML 报告"),
        ("output/filtered_nodes.log", "过滤日志"),
    ]
    
    all_exist = True
    for file_path, description in files_to_check:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"✅ {description}: {file_path} ({file_size} 字节)")
        else:
            print(f"❌ {description}: {file_path} (不存在)")
            all_exist = False
    
    print()
    return all_exist

def analyze_results():
    """分析清洗结果"""
    print("="*70)
    print("📊 分析清洗结果")
    print("="*70 + "\n")
    
    import json
    
    try:
        # 读取 JSON 结果
        with open("output/result.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        
        stats = data.get("stats", {})
        results = data.get("results", [])
        
        print("📈 统计数据:")
        print(f"  • 总节点数: {stats.get('total', 0)}")
        print(f"  • 含 IP 的节点: {stats.get('ip_only', 0)}")
        print(f"  • 含域名的节点: {stats.get('domain_only', 0)}")
        print(f"  • 风险节点: {stats.get('risky', 0)}")
        print(f"  • 正常节点: {stats.get('clean', 0)}")
        print(f"  • 被过滤节点: {stats.get('filtered', 0)}")
        
        print(f"\n✅ 清洗后有效节点: {len(results)} 条")
        
        if results:
            print("\n📍 样本节点信息 (前 5 个):")
            for i, result in enumerate(results[:5], 1):
                remark = result.get('remark', '未知')[:30]
                ip = result.get('ip', '❓')
                emoji = result.get('emoji', '❓')
                rating = result.get('rating', '未知')
                print(f"  {i}. [{emoji}] {remark} | IP: {ip} | 评级: {rating}")
        
        print()
        return True
    except Exception as e:
        print(f"❌ 分析失败: {e}\n")
        return False

def main():
    """主测试流程"""
    # 检查输入文件
    if not os.path.exists("output/raw_nodes.txt"):
        print("❌ 缺少输入文件: output/raw_nodes.txt\n")
        return False
    
    # 运行清洗脚本
    success = asyncio.run(test_clean_nodes())
    
    if not success:
        return False
    
    # 验证输出文件
    if not verify_output_files():
        print("⚠️ 部分输出文件缺失\n")
    
    # 分析结果
    analyze_results()
    
    print("="*70)
    print("✨ 测试完成！")
    print("="*70 + "\n")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️ 测试被中断\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 测试失败: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
