using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting; 
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;
using StackExchange.Redis;
using System.Data;

public class Program
{
    // Хранилище пользователей
    private static readonly List<User> _users = new();

    // --- 1. ТОЧКА ВХОДА: ЗАПУСК ХОСТА ---
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
        // Подключение к Redis
        var redis = ConnectionMultiplexer.Connect("localhost:6379");
        IDatabase db = redis.GetDatabase();
        db.StringSet("key", "Hi Redis");
        string ?value = db.StringGet("key");
        Console.WriteLine($"Key: {value}");
    }

    // --- 2. СТРОИТЕЛЬ ХОСТА ---
    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
        .ConfigureWebHostDefaults(webBuilder =>
        {
            // Установка порта по умолчанию
            webBuilder.UseUrls("http://localhost:8080");

            // --- КОНФИГУРАЦИЯ СЕРВИСОВ (DI) ---
            webBuilder.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddSignalR();
                services.AddSingleton<WSocket>();
                services.AddHsts(options =>
                {
                    options.Preload = true;
                    options.IncludeSubDomains = true;
                    options.MaxAge = TimeSpan.FromDays(366);
                });
                services.Configure<ForwardedHeadersOptions>(options =>
                {
                    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                    options.KnownProxies.Clear();
                });
            });

            // --- КОНФИГУРАЦИЯ КОНВЕЙЕРА ---
            webBuilder.Configure(app =>
            {
                var wsocket = app.ApplicationServices.GetRequiredService<WSocket>();
                
                _ = Task.Run(async() =>
                {
                    Console.WriteLine("[SERVER] Запуск фоновой задачи SignalR.");
                    await Task.Delay(5000);
                    await wsocket.AlertClients("Сервер готов и слушает. Добро пожаловать!");
                    await Task.Delay(10000);
                    await wsocket.AlertClients("Прошло 10 секунд. Система работает.");
                });

                app.UseForwardedHeaders();
                app.UseHsts();
                app.UseHttpsRedirection();

                app.Use(async (context, next) =>
                {
                    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                    context.Response.Headers["X-Frame-Options"] = "DENY";
                    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
                    context.Response.Headers["Referrer-Policy"] = "no-referrer";
                    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
                    await next();
                });

                app.Use((context, next) =>
                {
                    var maxBodyFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
                    if (maxBodyFeature != null && !maxBodyFeature.IsReadOnly)
                    {
                        maxBodyFeature.MaxRequestBodySize = 1024 * 1024;
                    }
                    return next();
                });

                app.UseRouting();
                
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapHub<ChatHub>("/Chat"); 

                    // --- Маршрутизация ---
                    endpoints.MapGet("/", async context =>
                    {
                        context.Response.ContentType = "application/json; charset=utf-8";
                        var encodedJson = JsonSerializer.Serialize(new { message = "Welcome to the Secure API endpoint." });
                        await context.Response.WriteAsync(encodedJson);
                    });

                    // Регистрация
                    endpoints.MapPost("/signup", async context =>
                    {
                        try
                        {
                            var userDto = await JsonSerializer.DeserializeAsync<UserDto>(context.Request.Body);

                            // 1. ПРОВЕРКА ОБЯЗАТЕЛЬНОСТИ ПОЛЕЙ: Требуем Username И Password
                            if (userDto == null || string.IsNullOrEmpty(userDto.Password) || string.IsNullOrEmpty(userDto.Username))
                            {
                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await context.Response.WriteAsync("Invalid data: Username and Password are required.");
                                return;
                            }
                            
                            // 2. ПРОВЕРКА СОВПАДЕНИЯ ПАРОЛЕЙ
                            if (userDto.ConfirmPassword != userDto.Password)
                            {
                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await context.Response.WriteAsync("Invalid data: Passwords do not match.");
                                return;
                            }

                            // 3. ПРОВЕРКА ПАРОЛЯ
                            if (userDto.Password.Length < 8)
                            {
                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await context.Response.WriteAsync("Invalid data: Password must contain at least 8 characters.");
                                return;
                            }

                            // 4. ПРОВЕРКА НИКНЕЙМА (Обязателен)
                            
                            if (userDto.Username.Length < 3)
                            {
                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await context.Response.WriteAsync("Invalid data: Username must contain at least 3 characters.");
                                return;
                            }

                            if (_users.Any(u => u.Username.Equals(userDto.Username, StringComparison.OrdinalIgnoreCase)))
                            {
                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await context.Response.WriteAsync("Invalid data: User account already exists or data is malformed."); 
                                return;
                            }
                            
                            // 5. ПРОВЕРКА EMAIL (Опциональна, проверяем только если поле не пустое)
                            if (!string.IsNullOrEmpty(userDto.Email))
                            {
                                if (!IsValidEmail(userDto.Email))
                                {
                                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                    await context.Response.WriteAsync("Invalid data: Invalid email format.");
                                    return;
                                }

                                if (_users.Any(u => u.Email.Equals(userDto.Email, StringComparison.OrdinalIgnoreCase)))
                                {
                                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                    await context.Response.WriteAsync("Invalid data: User account already exists or data is malformed.");
                                    return;
                                }
                            }

                            // 6. СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ
                            var newUser = new User
                            {
                                Id = Guid.NewGuid(),
                                Username = userDto.Username, // Гарантированно заполнен
                                // Email может быть пустой строкой, если не был предоставлен
                                Email = userDto.Email ?? "",
                                Password = HashPassword(userDto.Password),
                                RegistrationDate = DateTime.UtcNow
                            };

                            _users.Add(newUser);

                            context.Response.StatusCode = StatusCodes.Status201Created;
                            await context.Response.WriteAsync($"Регистрация успешна для: {newUser.Username}!");
                        }
                        catch (JsonException)
                        {
                            context.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await context.Response.WriteAsync("Invalid data: Request body is not valid JSON.");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ERROR] SIGNUP: {ex.Message}");
                            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                            await context.Response.WriteAsync("ERROR: Internal server error during signup.");
                        }
                    }); 

                    // Вход
                    endpoints.MapPost("/login", async context =>
                    {
                        var loginDto = await JsonSerializer.DeserializeAsync<LoginDto>(context.Request.Body);

                        if (loginDto == null || string.IsNullOrEmpty(loginDto.Identifier) || string.IsNullOrEmpty(loginDto.Password))
                        {
                            context.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await context.Response.WriteAsync("Invalid data (Identifier and Password required)");
                            return;
                        }

                        var user = _users.FirstOrDefault(u =>
                            u.Username.Equals(loginDto.Identifier, StringComparison.OrdinalIgnoreCase) ||
                            u.Email.Equals(loginDto.Identifier, StringComparison.OrdinalIgnoreCase));

                        if (user != null && VerifyPassword(loginDto.Password, user.Password))
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync($"Добро пожаловать, {user.Username ?? user.Email}!");
                            return;
                        }

                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync("Неверный логин/email или пароль.");
                    });

                    endpoints.MapFallback(async context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        context.Response.ContentType = "application/json; charset=utf-8";
                        var err = JsonSerializer.Serialize(new { message = "Not found" });
                        await context.Response.WriteAsync(err);
                    });
                });
            });
        });

    // --- БЕЗОПАСНОСТЬ И ВАЛИДАЦИЯ ---
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 100000;

    private static string HashPassword(string password)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            byte[] hashBytes = new byte[SaltSize + KeySize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, KeySize);

            return Convert.ToBase64String(hashBytes);
        }
    }

    private static bool VerifyPassword(string inputPassword, string storedHash)
    {
        try
        {
            byte[] hashBytes = Convert.FromBase64String(storedHash);
            if (hashBytes.Length < SaltSize + KeySize) return false;

            byte[] salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            byte[] storedHashOnly = new byte[KeySize];
            Array.Copy(hashBytes, SaltSize, storedHashOnly, 0, KeySize);

            byte[] inputHash = Rfc2898DeriveBytes.Pbkdf2(
                inputPassword,
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            return CryptographicOperations.FixedTimeEquals(inputHash, storedHashOnly);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        try
        {
            var emailAttribute = new System.ComponentModel.DataAnnotations.EmailAddressAttribute();
            return emailAttribute.IsValid(email);
        }
        catch
        {
            return false;
        }
    }
    
    // --- Модели Данных ---
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Email { get; set; } = "";
        public DateTime RegistrationDate { get; set; } = DateTime.UtcNow;
    }
    public class UserDto
    {
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        public string ConfirmPassword { get; set; } = ""; 
    }
    public class LoginDto
    {
        public string Identifier { get; set; } = ""; 
        public string Password { get; set; } = "";
    }
}           