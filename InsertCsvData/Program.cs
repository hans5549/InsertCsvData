using InsertCsvData.Interfaces;
using InsertCsvData.Services; // 假設 ICveMapper 在這個命名空間中
using InsertCsvData.Services.Database;
using Microsoft.Extensions.Configuration;

namespace InsertCsvData;

internal static class Program
{
    private static void Main(string[] args)
    {
        // 構建配置
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        // 從配置中獲取路徑和連線字串
        var userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cvePath = configuration["FilePaths:CvePath"];
        var failurePath = configuration["FilePaths:FailurePath"];
        var connectionString = configuration["ConnectionStrings:SqlConnection"];
        var dbType = configuration["Database:DbType"]; // 新增：從配置中讀取資料庫類型

        // 驗證配置是否完整
        if (string.IsNullOrEmpty(cvePath) || string.IsNullOrEmpty(failurePath) ||
            string.IsNullOrEmpty(connectionString) || string.IsNullOrEmpty(dbType))
        {
            Console.WriteLine("Error: File paths, connection string, or database type not properly configured in appsettings.json");
            return;
        }

        var fullCvePath = Path.Combine(userProfilePath, cvePath);
        var fullFailurePath = Path.Combine(userProfilePath, failurePath);

        // 初始化服務
        ICveMapper cveMapper = new CveMapperService();
        IDatabaseService dbService = new SqlDatabaseService(connectionString, dbType); // 傳遞 dbType

        // 處理所有 JSON 檔案
        ProcessAllJsonFiles(fullCvePath, fullFailurePath, cveMapper, dbService);

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }

    private static void ProcessAllJsonFiles(string cveDirectory, string failureDirectory, ICveMapper cveMapper, IDatabaseService dbService)
    {
        if (!Directory.Exists(cveDirectory))
        {
            Console.WriteLine($"Error: CVE directory not found: {cveDirectory}");
            return;
        }

        var jsonFiles = Directory.EnumerateFiles(cveDirectory, "*.json", SearchOption.AllDirectories).ToList();
        var totalFiles = jsonFiles.Count;
        var successCount = 0;
        var failureCount = 0;

        Console.WriteLine($"Found {totalFiles} JSON files to process.");

        foreach (var filePath in jsonFiles)
        {
            Console.WriteLine($"\nProcessing file: {Path.GetFileName(filePath)}");

            var mappingResult = cveMapper.MapCveToModel(filePath, failureDirectory);
            if (!mappingResult.IsSuccess || mappingResult.RootCve == null)
            {
                failureCount++;
                Console.WriteLine($"Failed to map {filePath}. Moved to failure directory.");
                continue;
            }

            try
            {
                dbService.InsertCveData(mappingResult.RootCve);
                successCount++;
                Console.WriteLine($"Successfully inserted data from {filePath} into database.");
            }
            catch (Exception ex)
            {
                failureCount++;
                Console.WriteLine($"Failed to insert data from {filePath}: {ex.Message}");
                MoveFileToFailureDirectory(filePath, failureDirectory, ex);
            }

            Console.WriteLine($"Progress: Processed {successCount + failureCount}/{totalFiles} | Success: {successCount} | Failed: {failureCount}");
        }

        Console.WriteLine($"\nProcessing completed. Total: {totalFiles}, Success: {successCount}, Failed: {failureCount}");
    }

    private static void MoveFileToFailureDirectory(string sourcePath, string failureDirectory, Exception exception)
    {
        try
        {
            if (!Directory.Exists(failureDirectory)) Directory.CreateDirectory(failureDirectory);
            var fileName = Path.GetFileName(sourcePath);
            var destPath = Path.Combine(failureDirectory, fileName);
            File.Move(sourcePath, destPath);

            var message = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Failed to move file: {sourcePath}\n" +
                          $"Error: {exception.Message}\n" +
                          $"Stack Trace: {exception.StackTrace}\n" +
                          $"------------------------\n";
            // 定義 log 檔案路徑，使用 failureDirectory 下的 failure-file-log.txt
            var logFilePath = Path.Combine(failureDirectory, "failure-file-log.txt");

            // 將錯誤訊息追加到檔案中（如果檔案不存在會自動建立）
            File.AppendAllText(logFilePath, message);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to move file {sourcePath} to failure directory: {ex.Message}");
        }
    }
}