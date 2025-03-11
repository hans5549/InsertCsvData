using InsertCsvData.Services;

namespace InsertCsvData;

internal class Program
{
    private static void Main(string[] args)
    {
        var cvePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads/cvelistV5-main(2021-2025)/cves");
        var failurePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads/cvelistV5-main(2021-2025)/failure");

        // 處理所有 JSON 檔案並顯示進度
        CveService.ProcessJsonFilesInDirectory(cvePath, failurePath);

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}