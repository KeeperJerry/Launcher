package launchserver.auth.provider;

import launcher.LauncherAPI;
import launcher.helper.VerifyHelper;
import launcher.serialize.config.entry.BlockConfigEntry;

import java.io.IOException;
import java.util.Objects;

public class DelegateAuthProvider extends AuthProvider
{
    private volatile AuthProvider delegate;

    DelegateAuthProvider(BlockConfigEntry block)
    {
        super(block);
    }

    @Override
    public AuthProviderResult auth(String login, String password, String ip, String profile) throws Throwable
    {
        return getDelegate().auth(login, password, ip, profile);
    }

    @Override
    public void close() throws IOException
    {
        AuthProvider delegate = this.delegate;
        if (delegate != null)
        {
            delegate.close();
        }
    }

    private AuthProvider getDelegate()
    {
        return VerifyHelper.verify(delegate, Objects::nonNull, "Delegate auth provider wasn't set");
    }

    @LauncherAPI
    public void setDelegate(AuthProvider delegate)
    {
        this.delegate = delegate;
    }
}
