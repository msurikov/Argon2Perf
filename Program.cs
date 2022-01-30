var passwordBytes = System.Text.Encoding.UTF8.GetBytes("Enough long password with special characters like !@#$%^&*() and digits 0123456789 for benchmark");
var salt = new byte[64];
using (var random = System.Security.Cryptography.RandomNumberGenerator.Create())
{
    random.GetBytes(salt);
}

Console.WriteLine("---");
Measure("PBKDF2: Iterations=10000,", () => PBKDF2Hash(passwordBytes, salt, iterations: 10000));
Measure("PBKDF2: Iterations=100000,", () => PBKDF2Hash(passwordBytes, salt, iterations: 100000));
Measure("PBKDF2: Iterations=310000,", () => PBKDF2Hash(passwordBytes, salt, iterations: 310000));

Console.WriteLine("---");
Measure("Isopoh Argon2d:", () => IsopohArgon2Hash(passwordBytes, salt, Isopoh.Cryptography.Argon2.Argon2Type.DataDependentAddressing));
Measure("Isopoh Argon2i:", () => IsopohArgon2Hash(passwordBytes, salt, Isopoh.Cryptography.Argon2.Argon2Type.DataIndependentAddressing));
Measure("Isopoh Argon2id:", () => IsopohArgon2Hash(passwordBytes, salt, Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing));

Console.WriteLine("---");
Measure("Konscious Argon2d:", () => KonsciousArgon2Hash(new Konscious.Security.Cryptography.Argon2d(passwordBytes), salt));
Measure("Konscious Argon2i:", () => KonsciousArgon2Hash(new Konscious.Security.Cryptography.Argon2i(passwordBytes), salt));
Measure("Konscious Argon2id:", () => KonsciousArgon2Hash(new Konscious.Security.Cryptography.Argon2id(passwordBytes), salt));

static byte[] PBKDF2Hash(byte[] passwordBytes, byte[] salt, int iterations)
{
	var hasher = new System.Security.Cryptography.Rfc2898DeriveBytes(passwordBytes, salt, iterations);
	return hasher.GetBytes(64);
}

static byte[] IsopohArgon2Hash(byte[] passwordBytes, byte[] salt, Isopoh.Cryptography.Argon2.Argon2Type type)
{
	var config = new Isopoh.Cryptography.Argon2.Argon2Config
	{
		Version = Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
		Password = passwordBytes,
		Salt = salt,
		Type = type,
		Threads = 1,
		TimeCost = 2,
		MemoryCost = 15*1024,
		Lanes = 1,
		HashLength = 64,
	};

	using (var hasher = new Isopoh.Cryptography.Argon2.Argon2(config))
	using (var hash = hasher.Hash())
	{
		return hash.Buffer;
	}
}

static byte[] KonsciousArgon2Hash(Konscious.Security.Cryptography.Argon2 hasher, byte[] salt)
{
	hasher.Salt = salt;
	hasher.DegreeOfParallelism = 1;
	hasher.MemorySize = 15*1024;
	hasher.Iterations = 2;
	return hasher.GetBytes(64);
}

static void Measure(string label, Action action)
{
	var runInterval = TimeSpan.FromSeconds(10);
	var stopTimeout = TimeSpan.FromSeconds(5);
	var degreeOfParallelism = Environment.ProcessorCount;
	
	int stop = 0;
	long count = 0;
	var threads = Enumerable
		.Range(0, degreeOfParallelism)
		.Select(_ => new Thread(() => {
			while (Interlocked.CompareExchange(ref stop, 0, 0) == 0)
			{
				action();
				Interlocked.Increment(ref count);
			}
		}))
		.ToList();

	Interlocked.Exchange(ref stop, 0);
	threads.ForEach(thread => { thread.Priority = ThreadPriority.BelowNormal; thread.Start(); });
	Thread.Sleep(runInterval);
	var performance = count / runInterval.TotalSeconds;
	Interlocked.Exchange(ref stop, 1);
	threads.ForEach(thread => thread.Join(stopTimeout));
	
	Console.WriteLine("{0} Threads={1}, Performance={2} per second", label, degreeOfParallelism, performance);
}
