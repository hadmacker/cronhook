using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using WebApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHostedService<TimedHostedService>();
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IHookRepository, InMemoryHookRepository>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/hooks", (HookRegistration reg) =>
{
    app.Services.GetRequiredService<IHookRepository>().AddWebHook(reg);
}).WithDisplayName("Add Webhook");
app.MapDelete("/hooks/{name}", (string name) =>
{
    app.Services.GetRequiredService<IHookRepository>().Delete(name);
}).WithDisplayName("Delete Webhook");
app.MapGet("/hooks", () =>
{
    return app.Services.GetRequiredService<IHookRepository>().GetHooks();
}).WithDisplayName("Get Webhooks");

app.MapPost("/whreceiver", (MessageBody model, HttpContext context) =>
    ReceiveWebhook(model, context, "/whreceiver", app))
.WithName("Webhook Receiver");

app.MapPost("/whreceiver2", (MessageBody model, HttpContext context) =>
    ReceiveWebhook(model, context, "/whreceiver2", app))
.WithName("Webhook Receiver Alternate");

app.Run();

string CalculateHmacSha256Signature(string data, string secretKey)
{
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
    {
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}

void ReceiveWebhook(MessageBody model, HttpContext context, string receiver, WebApplication app)
{
    app.Logger.LogInformation(model.Count.ToString());

    var Request = context.Request;
    var hookname = Request.Headers.TryGetValue("X-Hook-Name", out var hookNameValue) ? hookNameValue.FirstOrDefault() : "unset";

    try
    {
        var repository = app.Services.GetRequiredService<IHookRepository>();

        repository.GetHooks()
            .Where(h => h.Name.Equals(hookname))
            .ToList()
            .ForEach(hook =>
        {
            var secretKey = hook.Secret;

            // Get the X-Signature-256 header from the request
            var incomingSignature = Request.Headers["X-Hook-Signature-256"].ToString().Replace("sha256=", "");

            // Calculate the HMAC SHA256 signature for the received model
            var calculatedSignature = CalculateHmacSha256Signature(JsonSerializer.Serialize(model), secretKey);

            // Compare the calculated signature with the incoming signature
            if (string.Equals(incomingSignature, calculatedSignature, StringComparison.OrdinalIgnoreCase))
            {
                // Signature is valid
                app.Logger.LogInformation($"Received a valid message for {hook.Name}: {model}");
            }
            else
            {
                // Signature is invalid
                app.Logger.LogWarning($"Received an invalid message for {hook.Name} with model: {model}");
            }
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error processing the request.");
    }

}