package launchserver.command.auth;

import launcher.helper.LogHelper;
import launchserver.LaunchServer;
import launchserver.auth.provider.AuthProviderResult;
import launchserver.command.Command;

import java.util.UUID;

public final class AuthCommand extends Command
{
    public AuthCommand(LaunchServer server)
    {
        super(server);
    }

    @Override
    public String getArgsDescription()
    {
        return "<login> <password> <profile>";
    }

    @Override
    public String getUsageDescription()
    {
        return "Try to auth with specified login, password and profile";
    }

    @Override
    public void invoke(String... args) throws Throwable
    {
        verifyArgs(args, 3);
        String login = args[0];
        String password = args[1];
        String profile = args[2];

        // Authenticate
        AuthProviderResult result = server.config.authProvider.auth(login, password, "127.0.0.1", profile);
        UUID uuid = server.config.authHandler.auth(result);

        // Print auth successful message
        LogHelper.subInfo("UUID: %s, Username: '%s', Access Token: '%s'", uuid, result.username, result.accessToken);
    }
}
