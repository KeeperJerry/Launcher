package launchserver.auth.handler;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import launcher.serialize.config.entry.BlockConfigEntry;
import launcher.serialize.config.entry.StringConfigEntry;
import launchserver.auth.provider.AuthProviderResult;
import launchserver.auth.provider.AuthlibAuthProviderResult;
import launchserver.helpers.HTTPRequestHelper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class AuthlibAuthHandler extends AuthHandler
{
    private static java.net.URL URL;
    private static String joinUrl;

    public final HashMap<String, UUID> usernameToUUID = new HashMap<>();

    AuthlibAuthHandler(BlockConfigEntry block)
    {
        super(block);
        joinUrl = block.getEntryValue("joinUrl", StringConfigEntry.class);

        try
        {
            // Docs: https://wiki.vg/Protocol_Encryption#Client
            URL = new URL(joinUrl); // "https://sessionserver.mojang.com/session/minecraft/join"
        }
        catch (MalformedURLException e)
        {
            throw new InternalError(e);
        }
    }

    @Override
    public UUID auth(AuthProviderResult authResult) {
        if (authResult instanceof AuthlibAuthProviderResult) {
            AuthlibAuthProviderResult result = (AuthlibAuthProviderResult) authResult;
            usernameToUUID.put(result.username, result.uuid);
            return result.uuid;
        }
        return null;
    }

    @Override
    public UUID checkServer(String username, String serverID) {
        return UUID.fromString(serverID);
    }

    @Override
    public void close() {
    }

    @Override
    public boolean joinServer(String username, String accessToken, String serverID) throws IOException {
        JsonObject request = Json.object().
                add("agent", Json.object().add("name", "Minecraft").add("version", 1)).
                add("accessToken", accessToken).add("selectedProfile", usernameToUUID(username).toString().replace("-", "")).
                add("serverId", serverID);

        int response = HTTPRequestHelper.authJoinRequest(URL, request, "AuthLib");

        if (200 <= response && response < 300 )
        {
            return true;
        }
        else
        {
            authError("Empty Authlib Handler response");
        }
        return false;
    }

    @Override
    public UUID usernameToUUID(String username) {
        return usernameToUUID.get(username);
    }

    @Override
    public String uuidToUsername(UUID uuid) {
        for (Map.Entry<String, UUID> entry : usernameToUUID.entrySet()) {
            if (entry.getValue().equals(uuid)) return entry.getKey();
        }
        return null;
    }
}