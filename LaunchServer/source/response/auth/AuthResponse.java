package launchserver.response.auth;

import launcher.helper.IOHelper;
import launcher.helper.LogHelper;
import launcher.helper.SecurityHelper;
import launcher.helper.VerifyHelper;
import launcher.serialize.HInput;
import launcher.serialize.HOutput;
import launchserver.LaunchServer;
import launchserver.auth.AuthException;
import launchserver.auth.provider.AuthProvider;
import launchserver.auth.provider.AuthProviderResult;
import launchserver.response.Response;
import launchserver.response.profile.ProfileByUUIDResponse;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;
import java.util.UUID;

public final class AuthResponse extends Response
{
    private final String ip;

    public AuthResponse(LaunchServer server, long id, HInput input, HOutput output, String ip)
    {
        super(server, id, input, output);
        this.ip = ip;
    }

    private static String echo(int length)
    {
        char[] chars = new char[length];
        Arrays.fill(chars, '*');
        return new String(chars);
    }

    @Override
    public void reply() throws Throwable
    {
        String login = input.readString(255);
        byte[] encryptedPassword = input.readByteArray(SecurityHelper.CRYPTO_MAX_LENGTH);
        String profile = input.readString(255);

        // Decrypt password
        String password;
        try
        {
            password = IOHelper.decode(SecurityHelper.newRSADecryptCipher(server.privateKey).
                    doFinal(encryptedPassword));
        }
        catch (IllegalBlockSizeException | BadPaddingException ignored)
        {
            requestError("Password decryption error");
            return;
        }

        // Authenticate
        debug("Login: '%s', Password: '%s'", login, echo(password.length()));
        AuthProviderResult result;
        try
        {
            if (server.limiter.isLimit(ip))
            {
                AuthProvider.authError(server.config.authRejectString);
                return;
            }
            result = server.config.authProvider.auth(login, password, ip, profile);
            if (!VerifyHelper.isValidUsername(result.username))
            {
                AuthProvider.authError(String.format("Illegal result: '%s'", result.username));
                return;
            }
        }
        catch (AuthException e)
        {
            requestError(e.getMessage());
            return;
        }
        catch (Throwable exc)
        {
            LogHelper.error(exc);
            requestError("Internal auth provider error");
            return;
        }
        debug("Auth: '%s' -> '%s', '%s'", login, result.username, result.accessToken);

        // Authenticate on server (and get UUID)
        UUID uuid;
        try
        {
            uuid = server.config.authHandler.auth(result);
        }
        catch (AuthException e)
        {
            requestError(e.getMessage());
            return;
        }
        catch (Throwable exc)
        {
            LogHelper.error(exc);
            requestError("Internal auth handler error");
            return;
        }
        writeNoError(output);

        // Write profile and UUID
        ProfileByUUIDResponse.getProfile(server, uuid, result.username).write(output);
        output.writeASCII(result.accessToken, -SecurityHelper.TOKEN_STRING_LENGTH);
    }
}
