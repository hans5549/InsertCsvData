using InsertCsvData.Models;

namespace InsertCsvData.Interfaces;

public interface ICveMapper
{
    MappingResult MapCveToModel(string filePath, string failureDirectory);
}