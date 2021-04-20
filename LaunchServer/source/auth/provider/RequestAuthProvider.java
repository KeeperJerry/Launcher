package launchserver.auth.provider;

import launcher.helper.CommonHelper;
import launcher.helper.IOHelper;
import launcher.helper.SecurityHelper;
import launcher.serialize.config.entry.BlockConfigEntry;
import launcher.serialize.config.entry.StringConfigEntry;

import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RequestAuthProvider extends AuthProvider
{
    private final String url;
    private final Pattern response;

    RequestAuthProvider(BlockConfigEntry block)
    {
        super(block);
        url = block.getEntryValue("url", StringConfigEntry.class);
        response = Pattern.compile(block.getEntryValue("response", StringConfigEntry.class));

        // Verify is valid URL
        IOHelper.verifyURL(getFormattedURL("urlAuthLogin", "urlAuthPassword", "urlAuthIP", "urlAuthProfile"));
    }

    @Override
    public AuthProviderResult auth(String login, String password, String ip, String profile) throws IOException
    {
        String currentResponse = IOHelper.request(new URL(getFormattedURL(login, password, ip, profile)));

        // Match username
        Matcher matcher = response.matcher(currentResponse);
        return matcher.matches() && matcher.groupCount() >= 1 ?
                new AuthProviderResult(matcher.group("username"), SecurityHelper.randomStringToken()) :
                authError(currentResponse);
    }

    @Override
    public void close()
    {
        // Do nothing
    }

    private String getFormattedURL(String login, String password, String ip, String profile)
    {
        return CommonHelper.replace(url, "login", IOHelper.urlEncode(login), "password", IOHelper.urlEncode(password), "ip", IOHelper.urlEncode(ip), "profile", IOHelper.urlEncode(profile));
    }
}
