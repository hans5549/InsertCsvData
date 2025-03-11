using InsertCsvData.Interfaces;
using InsertCsvData.Models;
using Newtonsoft.Json;

namespace InsertCsvData.Services;

public class CveMapperService : ICveMapper
{
    public MappingResult MapCveToModel(string filePath, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(failureDirectory)) Directory.CreateDirectory(failureDirectory);

            using var streamReader = new StreamReader(filePath);
            using var jsonReader = new JsonTextReader(streamReader);
            var serializer = new JsonSerializer();
            var rootCve = serializer.Deserialize<Cve.RootCve>(jsonReader);

            if (rootCve?.CveMetadata == null)
                throw new Exception("Failed to parse JSON data or missing critical CVE metadata.");

            return new MappingResult
            {
                IsSuccess = true,
                OriginalFilePath = filePath,
                RootCve = rootCve
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error mapping {filePath}: {ex.Message}");
            MoveFileToFailureDirectory(filePath, failureDirectory);
            return new MappingResult
            {
                IsSuccess = false,
                OriginalFilePath = filePath,
                RootCve = null
            };
        }
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
        catch
        {
            // Silent failure
        }
    }
}