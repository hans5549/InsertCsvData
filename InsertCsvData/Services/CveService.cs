using InsertCsvData.Models;
using Newtonsoft.Json;

namespace InsertCsvData.Services;

public class CveService
{
    public static Cve.RootCve ParseCveData(string jsonData)
    {
        return JsonConvert.DeserializeObject<Cve.RootCve>(jsonData);
    }

    // 處理結果類型（簡化版）
    public class MappingResult
    {
        public bool IsSuccess { get; set; }
        public string OriginalFilePath { get; set; }
    }

    // 單個檔案的映射方法（簡化版）
    private static MappingResult MapCveToModels(string filePath, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(failureDirectory)) Directory.CreateDirectory(failureDirectory);

            // 使用流式讀取 JSON
            using (var streamReader = new StreamReader(filePath))
            using (var jsonReader = new JsonTextReader(streamReader))
            {
                var serializer = new JsonSerializer();
                var rootCve = serializer.Deserialize<Cve.RootCve>(jsonReader);

                if (rootCve == null || rootCve.CveMetadata == null)
                    throw new Exception("Failed to parse JSON data or missing critical CVE metadata.");

                var cveRecords = new List<Cve.CveRecord>
                {
                    new()
                    {
                        CveId = rootCve.CveMetadata.CveId ?? throw new Exception("CVE ID is missing."),
                        Title = rootCve.Containers.Cna?.Title ?? "Unknown Title",
                        DatePublished = rootCve.CveMetadata.DatePublished,
                        DateReserved = rootCve.CveMetadata.DateReserved,
                        DateUpdated = rootCve.CveMetadata.DateUpdated,
                        AssignerOrgId = rootCve.CveMetadata.AssignerOrgId,
                        AssignerShortName = rootCve.CveMetadata.AssignerShortName,
                        State = rootCve.CveMetadata.State
                    }
                };

                return new MappingResult
                {
                    IsSuccess = true,
                    OriginalFilePath = filePath
                };
            }
        }
        catch (Exception)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var fileName = Path.GetFileName(filePath);
                    var destPath = Path.Combine(failureDirectory, fileName);
                    File.Move(filePath, destPath);
                }
            }
            catch
            {
                // 移動失敗時靜默處理
            }

            return new MappingResult
            {
                IsSuccess = false,
                OriginalFilePath = filePath
            };
        }
    }

    /// <summary>
    /// 遍歷指定路徑下的所有子資料夾，處理 JSON 檔案，並即時顯示進度
    /// </summary>
    /// <param name="rootDirectory">根目錄路徑</param>
    /// <param name="failureDirectory">失敗檔案的目標目錄</param>
    public static void ProcessJsonFilesInDirectory(string rootDirectory, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(rootDirectory))
            {
                Console.WriteLine($"Error: Root directory not found: {rootDirectory}");
                return;
            }

            // 獲取所有 JSON 檔案
            var jsonFiles = Directory.EnumerateFiles(rootDirectory, "*.json", SearchOption.AllDirectories).ToList();
            var totalFiles = jsonFiles.Count;
            var successCount = 0;
            var failureCount = 0;
            var processedCount = 0;

            // 初始化進度顯示
            UpdateProgress(totalFiles, successCount, failureCount);

            foreach (var filePath in jsonFiles)
            {
                var result = MapCveToModels(filePath, failureDirectory);

                processedCount++;
                if (result.IsSuccess)
                    successCount++;
                else
                    failureCount++;

                // 即時更新進度
                UpdateProgress(totalFiles, successCount, failureCount);
            }

            // 最終結果
            Console.WriteLine(); // 換行
            Console.WriteLine(
                $"Processing completed. Total: {totalFiles}, Success: {successCount}, Failed: {failureCount}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing directory {rootDirectory}: {ex.Message}");
        }
    }

    // 更新並顯示進度
    private static void UpdateProgress(int total, int success, int failed)
    {
        Console.CursorLeft = 0; // 將光標移到行首
        Console.Write($"Progress: Processed {success + failed}/{total} | Success: {success} | Failed: {failed}");
    }
}