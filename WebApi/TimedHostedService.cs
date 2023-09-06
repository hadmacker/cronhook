using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebApi;

internal class TimedHostedService : IHostedService, IDisposable
{
    public ILogger<TimedHostedService> _logger { get; }

    private TimeSpan _interval;
    private HttpClient _httpClient;
    private IHookRepository _hookRepository;
    private int executionCount = 0;
    private Timer? _timer = null;

    public TimedHostedService(ILogger<TimedHostedService> logger, IConfiguration configuration, HttpClient httpClient, IHookRepository hookRepository)
    {
        _logger = logger;
        _interval = TimeSpan.FromSeconds(Int32.TryParse(configuration["periodSec"], out var periodSec) ? periodSec : 30);
        _httpClient = httpClient;
        _hookRepository = hookRepository;
    }

    public Task StartAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Timed Hosted Service running.");

        _timer = new Timer(DoWorkAsync, null, TimeSpan.Zero, _interval);

        return Task.CompletedTask;
    }

    private async void DoWorkAsync(object? state)
    {
        var count = Interlocked.Increment(ref executionCount);

        try
        {

            var message = new MessageBody
            {
                Count = count,
            };

            var hooks = _hookRepository.GetHooks();

            foreach (var hook in hooks)
            {
                try
                {
                    // foreach, send to a queue. then we process from queue is best.
                    var targetUri = hook.Url;
                    var secretKey = hook.Secret;
                    var requestBody = JsonSerializer.Serialize(message);
                    var signature = CalculateHmacSha256Signature(requestBody, secretKey);

                    var request = new HttpRequestMessage(HttpMethod.Post, new Uri("https://localhost:7258/whreceiver"));
                    request.Headers.Add("X-Hook-Signature-256", $"sha256={signature}");
                    request.Headers.Add("X-Hook-Name", hook.Name);
                    request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");
                    _logger.LogInformation($"Sending hook for {hook.Name} to {hook.Url}");
                    await _httpClient.SendAsync(request);
                }
                catch(HttpRequestException e)
                {
                    _logger.LogWarning(e, $"Http request failure");
                }
            }

            if(hooks.Count() == 0)
            {
                _logger.LogInformation("No hooks found");
            }

        }
        catch(Exception e)
        {
            _logger.LogWarning(e, $"Timed Hosted Service error");
        }
        _logger.LogInformation(
                    "Timed Hosted Service is working. Count: {Count}", count);
    }
    private string CalculateHmacSha256Signature(string data, string secretKey)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
        {
            var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }

    public Task StopAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Timed Hosted Service is stopping.");

        _timer?.Change(Timeout.Infinite, 0);

        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}