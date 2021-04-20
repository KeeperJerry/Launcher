package launchserver.auth.provider;

import launcher.helper.CommonHelper;
import launcher.helper.SecurityHelper;
import launcher.helper.VerifyHelper;
import launcher.serialize.config.entry.BlockConfigEntry;
import launcher.serialize.config.entry.ListConfigEntry;
import launcher.serialize.config.entry.StringConfigEntry;
import launchserver.auth.AuthException;
import launchserver.auth.MySQL8SourceConfig;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public final class MySQL8BcryptAuthProvider extends AuthProvider
{
    private final MySQL8SourceConfig mySQLHolder;
    private final String query;
    private final String[] queryParams;

    MySQL8BcryptAuthProvider(BlockConfigEntry block)
    {
        super(block);
        mySQLHolder = new MySQL8SourceConfig("authProviderPool", block);

        query = VerifyHelper.verify(block.getEntryValue("query", StringConfigEntry.class),
                VerifyHelper.NOT_EMPTY, "MySQL query can't be empty");
        queryParams = block.getEntry("queryParams", ListConfigEntry.class).
                stream(StringConfigEntry.class).toArray(String[]::new);
    }

    @Override
    public AuthProviderResult auth(String login, String password, String ip, String profile) throws SQLException, AuthException
    {
        try (Connection c = mySQLHolder.getConnection(); PreparedStatement s = c.prepareStatement(query))
        {
            String[] replaceParams = {"login", login, "password", password, "ip", ip};
            for (int i = 0; i < queryParams.length; i++)
            {
                s.setString(i + 1, CommonHelper.replace(queryParams[i], replaceParams));
            }

            // Execute SQL query
            s.setQueryTimeout(MySQL8SourceConfig.TIMEOUT);
            try (ResultSet set = s.executeQuery())
            {
                return set.next() ? BCrypt.checkpw(password, "$2a" + set.getString(1).substring(3)) ? new AuthProviderResult(set.getString(2), SecurityHelper.randomStringToken()) : authError("Incorrect username or password") : authError("Incorrect username or password");
            }
        }
    }

    @Override
    public void close()
    {
        mySQLHolder.close();
    }
}
