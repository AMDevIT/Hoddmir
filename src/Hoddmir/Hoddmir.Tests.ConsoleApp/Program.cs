using Hoddmir.Tests.ConsoleApp;

Console.WriteLine("Generating test data...");

TestProvider testProvider = new();
Console.WriteLine("Generating fixed length data...");
await testProvider.CreateTestStoreAsync(useFastArgon: false);
Console.WriteLine("Generating random data...");
await testProvider.CreateTestRandomStoreAsync(useFastArgon: false);
Console.WriteLine("Generated test data successfully.");