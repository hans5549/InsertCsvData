namespace InsertCsvData.Models;

public class MappingResult
{
    public bool IsSuccess { get; set; }
    public string OriginalFilePath { get; set; }
    public Cve.RootCve? RootCve { get; set; } // 新增屬性儲存映射後的模型
}