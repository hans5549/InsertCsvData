using InsertCsvData.Interfaces;
using InsertCsvData.Services;
using InsertCsvData.Services.Database;
using Microsoft.Extensions.Configuration;

namespace InsertCsvData;

internal static class Program
{
    private static void Main(string[] args)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        var userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cvePath = configuration["FilePaths:CvePath"];
        var failurePath = configuration["FilePaths:FailurePath"];
        var connectionString = configuration["ConnectionStrings:DefaultConnection"];

        if (string.IsNullOrEmpty(cvePath) || string.IsNullOrEmpty(failurePath) || string.IsNullOrEmpty(connectionString))
        {
            Console.WriteLine("Error: File paths or connection string not properly configured in appsettings.json");
            return;
        }

        var fullCvePath = Path.Combine(userProfilePath, cvePath);
        var fullFailurePath = Path.Combine(userProfilePath, failurePath);

        ICveMapper cveMapper = new CveMapperService();
        IDatabaseService dbService = new SqlDatabaseService(connectionString);

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
                MoveFileToFailureDirectory(filePath, failureDirectory);
            }

            Console.WriteLine($"Progress: Processed {successCount + failureCount}/{totalFiles} | Success: {successCount} | Failed: {failureCount}");
        }

        Console.WriteLine($"\nProcessing completed. Total: {totalFiles}, Success: {successCount}, Failed: {failureCount}");
    }

    private static void MoveFileToFailureDirectory(string sourcePath, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(failureDirectory)) Directory.CreateDirectory(failureDirectory);
            var fileName = Path.GetFileName(sourcePath);
            var destPath = Path.Combine(failureDirectory, fileName);
            File.Move(sourcePath, destPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to move file {sourcePath} to failure directory: {ex.Message}");
        }
    }
}