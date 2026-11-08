using Hoddmir.Tests.ConsoleApp;

TestProvider testProvider = new();
await testProvider.VerifyFileStoreLifecycleAsync();

Console.WriteLine("Generating test data...");
Console.WriteLine("Generating fixed length data...");
await testProvider.CreateTestStoreAsync(useFastArgon: false);
Console.WriteLine("Generating random data...");
await testProvider.CreateTestRandomStoreAsync(useFastArgon: false);
Console.WriteLine("Generated test data successfully.");
