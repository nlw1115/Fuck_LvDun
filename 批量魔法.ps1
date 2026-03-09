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
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".ico",
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

public static class FileCheckerEngineV5 {
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
        } catch (AggregateException aex) {
            Console.WriteLine("\n扫描过程中发生错误 (AggregateException):");
            foreach (var inner in aex.Flatten().InnerExceptions) {
                Console.WriteLine("  " + inner.GetType().FullName + ": " + inner.Message);
                if (inner is IOException || inner is UnauthorizedAccessException) {
                    Console.WriteLine("    Path-related error, continue scanning...");
                }
            }
        } catch (Exception ex) {
            Console.WriteLine("\n扫描过程中发生错误: " + ex.ToString());
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
        // 移除"含0即加密"的激进判断，避免误判正常二进制文件
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

                // 图片格式：统一检查常见图片魔数，支持扩展名不匹配的情况（例如 .png 实为 .jpg）
                bool isImage = false;
                if (StartsWithBytes(header, headerRead, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) isImage = true; // PNG
                else if (headerRead >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF) isImage = true; // JPEG
                else if (StartsWithBytes(header, headerRead, new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }) || 
                         StartsWithBytes(header, headerRead, new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 })) isImage = true; // GIF
                else if (StartsWithBytes(header, headerRead, new byte[] { 0x42, 0x4D })) isImage = true; // BMP
                else if (headerRead >= 12 &&
                         header[0] == 0x52 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x46 &&
                         header[8] == 0x57 && header[9] == 0x45 && header[10] == 0x42 && header[11] == 0x50) isImage = true; // WebP
                else if (headerRead >= 4 &&
                         header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x01 && header[3] == 0x00) isImage = true; // ICO

                if ((ext.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".bmp", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".webp", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".ico", StringComparison.OrdinalIgnoreCase))) {
                     if (isImage) return false;
                }

                // 文本格式：UTF-16/UTF-8 BOM 或控制字符占比低，视为未加密（UTF-16 含大量 0x00、含 null 的文本均合法）
                if ((ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) || ext.Equals(".csv", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".md", StringComparison.OrdinalIgnoreCase) || ext.Equals(".py", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".c", StringComparison.OrdinalIgnoreCase) || ext.Equals(".h", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".cpp", StringComparison.OrdinalIgnoreCase) || ext.Equals(".cc", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".pyx", StringComparison.OrdinalIgnoreCase) || ext.Equals(".pxd", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".cs", StringComparison.OrdinalIgnoreCase) || ext.Equals(".config", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".csproj", StringComparison.OrdinalIgnoreCase) || ext.Equals(".f", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".hpp", StringComparison.OrdinalIgnoreCase))) {
                    if (headerRead >= 2 && header[0] == 0xFF && header[1] == 0xFE) return false;  // UTF-16 LE BOM
                    if (headerRead >= 2 && header[0] == 0xFE && header[1] == 0xFF) return false;  // UTF-16 BE BOM
                    if (headerRead >= 3 && header[0] == 0xEF && header[1] == 0xBB && header[2] == 0xBF) return false;  // UTF-8 BOM
                    int ctrlCount = 0;
                    for (int i = 0; i < headerRead; i++) {
                        if (header[i] < 32 && header[i] != 9 && header[i] != 10 && header[i] != 13) ctrlCount++;
                    }
                    if (((double)ctrlCount / headerRead) <= 0.15) return false;  // 控制字符少，视为明文
                }
            }

            return LooksLikeEncryptedByHeuristic(header, headerRead);
        } catch {
            return false;
        }
    }
}
'

if (-not ("FileCheckerEngineV5" -as [type])) {
    Add-Type -TypeDefinition $csharpSource
}

# 1. 扫描并筛选加密文件
Write-Host "正在启动极速扫描模式..." -ForegroundColor Cyan
Write-Host "目标路径: $AbsInputPath"

$FilesToDecrypt = @()

if ((Get-Item $AbsInputPath).PSIsContainer) {
    # 使用 C# 静态方法进行全速扫描
    $FilesToDecrypt = [FileCheckerEngineV5]::FastScan($AbsInputPath, $TargetExtensions)
} else {
    # 单个文件
    if ($AbsInputPath.ToLower().Substring($AbsInputPath.LastIndexOf(".")) -in $TargetExtensions) {
        if ([FileCheckerEngineV5]::IsEncrypted($AbsInputPath)) {
            $FilesToDecrypt += $AbsInputPath
        }
    }
}

Write-Progress -Activity "正在扫描" -Completed
$TotalScanned = if ((Get-Item $AbsInputPath).PSIsContainer) { [FileCheckerEngineV5]::ScannedCount } else { 1 }

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
import tempfile

MAX_WORKERS = $MaxWorkers
FILE_LIST_PATH = r'$FileListFile'

# 辅助批处理路径，在 main() 里初始化；批处理从 ops 文件读 src/dst 并批量 move
MOVE_HELPER_BAT = None

def _make_move_helper_bat():
    """创建辅助批处理：%1=ops 文件（GBK），奇数行=src，偶数行=dst；内部批量 move 并输出 OK/FAIL。
    这样只启动一次 cmd，避免“每文件一次 cmd + 多个临时文件”带来的开销，同时仍使用 cmd move 触发系统钩子解密。
    """
    fd, path = tempfile.mkstemp(suffix='.bat')
    try:
        with os.fdopen(fd, 'w', newline='\r\n', encoding='ascii') as f:
            f.write('@echo off\r\n')
            f.write('setlocal DisableDelayedExpansion\r\n')
            f.write('set "ops=%~1"\r\n')
            f.write('if "%ops%"=="" exit /b 2\r\n')
            f.write('set "src="\r\n')
            f.write('set "dst="\r\n')
            f.write('set state=0\r\n')
            f.write('for /f "usebackq delims= eol=" %%L in ("%ops%") do call :handleLine "%%L"\r\n')
            f.write('exit /b 0\r\n')
            f.write(':handleLine\r\n')
            f.write('if "%state%"=="1" goto doMove\r\n')
            f.write('set "src=%~1"\r\n')
            f.write('set state=1\r\n')
            f.write('exit /b\r\n')
            f.write(':doMove\r\n')
            f.write('set "dst=%~1"\r\n')
            f.write('setlocal EnableDelayedExpansion\r\n')
            f.write('move /y "!src!" "!dst!" >nul 2>&1\r\n')
            f.write('if errorlevel 1 (\r\n')
            f.write('  echo FAIL !errorlevel! "!dst!"\r\n')
            f.write(') else (\r\n')
            f.write('  echo OK "!dst!"\r\n')
            f.write(')\r\n')
            f.write('endlocal\r\n')
            f.write('set state=0\r\n')
            f.write('exit /b\r\n')
        return path
    except Exception:
        os.close(fd)
        raise

def _run_cmd_move_batch(helper_bat, pairs, startupinfo):
    """批量执行 cmd move：pairs=[(src_tmp, dst), ...]。
    返回 (ok_dsts:set, fail_info:list[(code:int, dst:str)])。
    """
    enc = 'gbk'  # cmd 读取 bat 输出/以及 ops 文件时的常见代码页（中文 Windows 一般为 GBK）
    ops_path = None
    try:
        fd, ops_path = tempfile.mkstemp(suffix='.ops'); os.close(fd)
        with open(ops_path, 'w', encoding=enc, newline='\r\n') as f:
            for src, dst in pairs:
                f.write(src + '\r\n')
                f.write(dst + '\r\n')

        proc = subprocess.run(
            ['cmd', '/c', helper_bat, ops_path],
            check=False,
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        out = (proc.stdout or b'').decode(enc, errors='ignore')
        ok = set()
        fail = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # OK "dst"
            if line.startswith('OK '):
                q1 = line.find('"')
                q2 = line.rfind('"')
                if q1 != -1 and q2 > q1:
                    ok.add(line[q1+1:q2])
                continue
            # FAIL <code> "dst"
            if line.startswith('FAIL '):
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        code = int(parts[1])
                    except Exception:
                        code = 1
                else:
                    code = 1
                q1 = line.find('"')
                q2 = line.rfind('"')
                dst = None
                if q1 != -1 and q2 > q1:
                    dst = line[q1+1:q2]
                if dst:
                    fail.append((code, dst))
                continue
        return ok, fail
    finally:
        if ops_path and os.path.exists(ops_path):
            try:
                os.remove(ops_path)
            except Exception:
                pass

def _prepare_temp(file_path):
    """
    读取并写出临时文件（不做 move）。
    返回 (temp_path, file_path, ext_lower) 或 None。
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
            
        # 3. 去掉只读（若有）
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

        return temp_path, file_path, os.path.splitext(file_path)[1].lower()
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

    global MOVE_HELPER_BAT
    if os.name == 'nt':
        try:
            MOVE_HELPER_BAT = _make_move_helper_bat()
        except Exception as e:
            print(f"创建 move 辅助批处理失败: {e}")
            return
    else:
        print("当前仅支持 Windows 下通过 cmd move 触发解密。")
        return

    print(f"Python 引擎启动。正在批量解密 {len(files)} 个文件 (线程数: {MAX_WORKERS})...")
    
    stats = {}
    success_count = 0
    start_time = time.time()
    
    try:
        # 1) 并行生成 .tmp（读取明文 + 写临时文件）
        pairs = []
        ext_by_dst = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(_prepare_temp, f): f for f in files}
            for future in concurrent.futures.as_completed(future_to_file):
                res = future.result()
                if res:
                    tmp_path, dst_path, ext = res
                    pairs.append((tmp_path, dst_path))
                    ext_by_dst[dst_path] = ext

        if not pairs:
            end_time = time.time()
            duration = end_time - start_time
            print("\n" + "=" * 30)
            print("       解密结果统计       ")
            print("=" * 30)
            print("-" * 30)
            print(f"成功解密: 0 / {len(files)}")
            print(f"耗时: {duration:.2f} 秒")
            return

        # 2) 单次 cmd 批量 move 覆盖（触发系统钩子解密）
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        ok_dsts, fail_info = _run_cmd_move_batch(MOVE_HELPER_BAT, pairs, startupinfo)

        fail_set = set()
        for code, dst in fail_info:
            fail_set.add(dst)
            print(f"处理失败: {dst} - cmd move 失败，退出码 {code}")

        for dst in ok_dsts:
            ext = ext_by_dst.get(dst)
            if ext:
                print(f"已解密: {dst}")
                success_count += 1
                stats[ext] = stats.get(ext, 0) + 1

        # 3) 清理 move 失败遗留的 .tmp
        for tmp, dst in pairs:
            if dst in fail_set and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass

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
    finally:
        if MOVE_HELPER_BAT and os.path.exists(MOVE_HELPER_BAT):
            try:
                os.remove(MOVE_HELPER_BAT)
            except Exception:
                pass

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
