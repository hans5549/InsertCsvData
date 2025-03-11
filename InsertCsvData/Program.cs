using InsertCsvData.Services;
using Microsoft.Extensions.Configuration;

namespace InsertCsvData;

internal static class Program
{
    private static void Main(string[] args)
    {
        // Build configuration
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        // Get file paths from configuration
        var userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cvePath = configuration["FilePaths:CvePath"];
        var failurePath = configuration["FilePaths:FailurePath"];

        if (string.IsNullOrEmpty(cvePath) || string.IsNullOrEmpty(failurePath))
        {
            Console.WriteLine("Error: File paths not properly configured in appsettings.json");
            return;
        }

        var fullCvePath = Path.Combine(userProfilePath, cvePath);
        var fullFailurePath = Path.Combine(userProfilePath, failurePath);

        // 處理所有 JSON 檔案並顯示進度
        CveService.ProcessJsonFilesInDirectory(fullCvePath, fullFailurePath);

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}