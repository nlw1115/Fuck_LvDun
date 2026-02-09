# PowerShell文件解密脚本
# 递归查找指定文件夹下的特定后缀文件
# 使用 PowerShell 检测文件是否加密（针对透明加密场景），调用 Python 进行解密
# 使用方法: .\批量魔法.ps1 "文件夹或文件路径"
param(
    [Parameter(Mandatory=$true)]
    [string]$InputPath
)

# ================= 配置区域 =================
# 在这里定义需要处理的文件后缀（小写，包含点号）
$TargetExtensions = @(
    ".txt",
    ".py",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".pyx",
    ".csv",
    ".pxd",
    ".cs",
    ".config",
    ".csproj",
    ".f",
    ".hpp",
    ".md",
    ".doc",
    ".docx",
    ".pptx",
    ".xls",
    ".xlsx",
    ".pdf"
)
# 线程数配置 (Python解密时的并发数)
$MaxWorkers = 16
# ===========================================

# 检查 Python 环境
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "错误: 未找到 Python 环境，请确保 Python 已安装并添加到 PATH。"
    exit 1
}

# 获取绝对路径
$targetItem = Get-Item $InputPath -ErrorAction SilentlyContinue
if (-not $targetItem) {
    Write-Error "错误: 路径不存在 - $InputPath"
    exit 1
}
$AbsInputPath = $targetItem.FullName

# 函数: 检测文件是否加密
# 使用 C# 代码加速检测 (PowerShell 原生 loop 和 Get-Content 速度较慢)
$csharpSource = '
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

public static class FileCheckerEngineV4 {
    private static int _scannedCount = 0;
    private static int _encryptedCount = 0;
    public static int ScannedCount { get { return _scannedCount; } }
    public static int EncryptedCount { get { return _encryptedCount; } }

    public static string[] FastScan(string rootPath, string[] extensions) {
        var encryptedFiles = new ConcurrentBag<string>();
        var validExtensions = new HashSet<string>(extensions, StringComparer.OrdinalIgnoreCase);
        _scannedCount = 0;
        _encryptedCount = 0;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("C# engine: scanning file system...");
        Console.ResetColor();

        try {
            // 使用 EnumerateFiles 流式获取文件，避免一次性加载所有 FileInfo 带来的内存和时间开销
            var files = Directory.EnumerateFiles(rootPath, "*.*", SearchOption.AllDirectories);

            // 并行处理文件检查
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount * 2 }, (file) => {
                // 1. 扩展名预筛选 (极快)
                string ext = Path.GetExtension(file);
                if (string.IsNullOrEmpty(ext) || !validExtensions.Contains(ext)) {
                    return;
                }

                int current = Interlocked.Increment(ref _scannedCount);
                if (current % 1000 == 0) {
                    Console.Write("\rScanned: " + current + " files | Encrypted: " + _encryptedCount);
                }

                // 2. 内容检测 (IO + CPU)
                if (IsEncrypted(file)) {
                    Interlocked.Increment(ref _encryptedCount);
                    encryptedFiles.Add(file);
                }
            });
            
            Console.WriteLine("\rScanned: " + _scannedCount + " files | Encrypted: " + _encryptedCount);
            Console.WriteLine();
        } catch (Exception ex) {
            Console.WriteLine("\n扫描过程中发生错误: " + ex.Message);
        }

        return encryptedFiles.ToArray();
    }

    private static bool StartsWithAscii(byte[] buffer, int length, string prefix) {
        if (buffer == null || length <= 0 || prefix == null) return false;
        if (length < prefix.Length) return false;
        for (int i = 0; i < prefix.Length; i++) {
            if (buffer[i] != (byte)prefix[i]) return false;
        }
        return true;
    }

    private static bool StartsWithBytes(byte[] buffer, int length, byte[] prefix) {
        if (buffer == null || prefix == null) return false;
        if (length < prefix.Length) return false;
        for (int i = 0; i < prefix.Length; i++) {
            if (buffer[i] != prefix[i]) return false;
        }
        return true;
    }

    private static bool ContainsBytes(byte[] buffer, int length, byte[] pattern) {
        if (buffer == null || pattern == null) return false;
        if (length <= 0 || pattern.Length == 0) return false;
        if (length < pattern.Length) return false;
        int lastStart = length - pattern.Length;
        for (int i = 0; i <= lastStart; i++) {
            bool ok = true;
            for (int j = 0; j < pattern.Length; j++) {
                if (buffer[i + j] != pattern[j]) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }

    private static bool LooksLikeEncryptedByHeuristic(byte[] buffer, int bytesRead) {
        if (bytesRead <= 0) return false;
        for (int i = 0; i < bytesRead; i++) {
            if (buffer[i] == 0) return true;
        }
        int controlCount = 0;
        for (int i = 0; i < bytesRead; i++) {
            byte b = buffer[i];
            if (b < 32 && b != 9 && b != 10 && b != 13) {
                controlCount++;
            }
        }
        return ((double)controlCount / bytesRead) > 0.05;
    }

    public static bool IsEncrypted(string path) {
        try {
            string ext = Path.GetExtension(path) ?? "";
            byte[] header = new byte[8192];
            int headerRead = 0;

            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
                headerRead = fs.Read(header, 0, header.Length);
                if (headerRead == 0) return false;

                if (ext.Equals(".pdf", StringComparison.OrdinalIgnoreCase) && StartsWithAscii(header, headerRead, "%PDF-")) {
                    byte[] encrypt = Encoding.ASCII.GetBytes("/Encrypt");
                    if (ContainsBytes(header, headerRead, encrypt)) return true;

                    long len = fs.Length;
                    int tailSize = (int)Math.Min(1024 * 1024, len);
                    if (tailSize > 0) {
                        byte[] tail = new byte[tailSize];
                        fs.Seek(-tailSize, SeekOrigin.End);
                        int tailRead = fs.Read(tail, 0, tail.Length);
                        if (tailRead > 0 && ContainsBytes(tail, tailRead, encrypt)) return true;
                    }
                    return false;
                }

                if ((ext.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".pptx", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase)) &&
                    StartsWithBytes(header, headerRead, new byte[] { 0x50, 0x4B })) {
                    return false;
                }

                if ((ext.Equals(".doc", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".xls", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".ppt", StringComparison.OrdinalIgnoreCase)) &&
                    StartsWithBytes(header, headerRead, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) {
                    return false;
                }
            }

            return LooksLikeEncryptedByHeuristic(header, headerRead);
        } catch {
            return false;
        }
    }
}
'

if (-not ("FileCheckerEngineV4" -as [type])) {
    Add-Type -TypeDefinition $csharpSource
}

# 1. 扫描并筛选加密文件
Write-Host "正在启动极速扫描模式..." -ForegroundColor Cyan
Write-Host "目标路径: $AbsInputPath"

$FilesToDecrypt = @()

if ((Get-Item $AbsInputPath).PSIsContainer) {
    # 使用 C# 静态方法进行全速扫描
    $FilesToDecrypt = [FileCheckerEngineV4]::FastScan($AbsInputPath, $TargetExtensions)
} else {
    # 单个文件
    if ($AbsInputPath.ToLower().Substring($AbsInputPath.LastIndexOf(".")) -in $TargetExtensions) {
        if ([FileCheckerEngineV4]::IsEncrypted($AbsInputPath)) {
            $FilesToDecrypt += $AbsInputPath
        }
    }
}

Write-Progress -Activity "正在扫描" -Completed
$TotalScanned = [FileCheckerEngineV4]::ScannedCount

if ($FilesToDecrypt.Count -eq 0) {
    Write-Host "扫描完成。未发现加密文件 (共扫描 $TotalScanned 个文件)。" -ForegroundColor Green
    exit
}

Write-Host "扫描完成。发现 $($FilesToDecrypt.Count) 个加密文件 (共扫描 $TotalScanned 个文件)。" -ForegroundColor Yellow

# 2. 将待处理文件列表写入临时文件
$FileListFile = [System.IO.Path]::GetTempFileName()
$FilesToDecrypt | Out-File -FilePath $FileListFile -Encoding UTF8

# 3. 准备 Python 脚本
# Python 脚本负责：读取文件列表 -> 读取文件(触发解密) -> 原位写回
$pythonScript = @"
import sys
import os
import concurrent.futures
import time
import subprocess
import stat

MAX_WORKERS = $MaxWorkers
FILE_LIST_PATH = r'$FileListFile'

def refresh_file(file_path):
    """
    读取并原位写回文件。
    策略优化：
    1. Python 读取文件内容 (获取明文) 并写入临时文件。
    2. 使用 cmd.exe 的 move 命令进行覆盖。
       (cmd.exe 启动速度远快于 PowerShell，且能达到同样的“外部进程覆盖”效果)
    """
    try:
        file_path = file_path.strip()
        if not file_path: return None
        temp_path = file_path + ".tmp"
        
        # 1. 读取 (获取明文)
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # 2. 写入临时文件
        with open(temp_path, 'wb') as f:
            f.write(data)
            
        # 3. 使用 cmd.exe 覆盖
        # cmd /c move /y "temp" "dest"
        # 注意：cmd 对路径中的特殊字符处理较弱，但一般路径没问题。
        # 如果路径包含空格，需要用引号包裹。
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        try:
            subprocess.run(
                ['attrib', '-R', file_path],
                check=False,
                startupinfo=startupinfo,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

        cmd = ['cmd', '/c', 'move', '/y', temp_path, file_path]
        
        try:
            subprocess.run(
                cmd,
                check=True,
                startupinfo=startupinfo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            out = (e.stdout or b"")
            err = (e.stderr or b"")
            try:
                out_s = out.decode("gbk", errors="ignore").strip()
            except Exception:
                out_s = ""
            try:
                err_s = err.decode("gbk", errors="ignore").strip()
            except Exception:
                err_s = ""
            msg = f"cmd move 失败，退出码 {e.returncode}"
            if out_s:
                msg += f" | stdout: {out_s}"
            if err_s:
                msg += f" | stderr: {err_s}"
            raise RuntimeError(msg) from e
            
        return os.path.splitext(file_path)[1].lower()
    except Exception as e:
        print(f"处理失败: {file_path} - {e}")
        # 如果失败，尝试清理临时文件
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        return None

def main():
    try:
        with open(FILE_LIST_PATH, 'r', encoding='utf-8') as f:
            # 读取文件列表 (处理 BOM 和空白)
            content = f.read()
            if content.startswith('\ufeff'):
                content = content[1:]
            files = [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(f"无法读取文件列表: {e}")
        return

    print(f"Python 引擎启动。正在批量解密 {len(files)} 个文件 (线程数: {MAX_WORKERS})...")
    
    stats = {}
    success_count = 0
    start_time = time.time()
    
    # 使用线程池并发执行 cmd 覆盖
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(refresh_file, f): f for f in files}
        
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            ext = future.result()
            if ext:
                print(f"已解密: {file_path}")
                success_count += 1
                stats[ext] = stats.get(ext, 0) + 1

    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 30)
    print("       解密结果统计       ")
    print("=" * 30)
    for ext, count in stats.items():
        print(f"{ext:<6} 文件数: {count}")
    print("-" * 30)
    print(f"成功解密: {success_count} / {len(files)}")
    print(f"耗时: {duration:.2f} 秒")

if __name__ == '__main__':
    main()
"@

# 4. 执行 Python 脚本
$TempPythonFile = [System.IO.Path]::GetTempFileName() + ".py"
$pythonScript | Out-File -FilePath $TempPythonFile -Encoding UTF8

try {
    python $TempPythonFile
} finally {
    # 清理
    if (Test-Path $TempPythonFile) { Remove-Item $TempPythonFile -Force }
    if (Test-Path $FileListFile) { Remove-Item $FileListFile -Force }
}
