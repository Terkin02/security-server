using System;
using Microsoft.AspNetCore.SignalR;
using System.Security.Cryptography;
using System.Text.Json;

public class WSocket
    {
        private readonly IHubContext<ChatHub> _hubContext;
        public WSocket(IHubContext<ChatHub> hubContext)
        {
            _hubContext = hubContext;
        }

        public async Task AlertClients(string systemMessage)
        {
            Console.WriteLine($"[SERVER] Отправка системного уведомления: {systemMessage}");
            await _hubContext.Clients.All.SendAsync("SystemNotification", "SERVER_SYSTEM", systemMessage);
        }
    }
public class ChatHub : Hub
{   
    private const string BotUser = "👀Собеседник";
    private const string BotMessage = "👋"; 
    public async Task SendMessage(string user, string message)
    {
        Console.WriteLine($"[HUB] Message received from {user}: {message}");
        await Clients.All.SendAsync("ReceiveMessage", user, message);
        await Task.Delay(500);
        await Clients.All.SendAsync("ReceiveMessage", BotUser, BotMessage);
    }

    public override Task OnConnectedAsync()
    {
        Console.WriteLine($"[HUB] Client connected: {Context.ConnectionId}");
        return base.OnConnectedAsync();
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        Console.WriteLine($"[HUB] Client disconnected: {Context.ConnectionId}");
        return base.OnDisconnectedAsync(exception);
    }
}
