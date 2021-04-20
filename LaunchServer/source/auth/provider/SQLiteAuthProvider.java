package launchserver.auth.provider;

import launcher.helper.CommonHelper;
import launcher.helper.LogHelper;
import launcher.helper.SecurityHelper;
import launcher.helper.VerifyHelper;
import launcher.serialize.config.entry.BlockConfigEntry;
import launcher.serialize.config.entry.ListConfigEntry;
import launcher.serialize.config.entry.StringConfigEntry;
import launchserver.auth.AuthException;
import launchserver.auth.MySQLSourceConfig;

import java.sql.*;

public final class SQLiteAuthProvider extends AuthProvider
{
    private final String query;
    private final String[] queryParams;
    private final Connection sqliteconnection;

    public SQLiteAuthProvider(BlockConfigEntry block)
    {
        super(block);

        try
        {
            Class.forName("org.sqlite.JDBC");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            //System.out.println("Here");
        }

        Connection sqliteconnection1;
        try
        {
            sqliteconnection1 = DriverManager.getConnection("jdbc:sqlite:" + block.getEntryValue("path", StringConfigEntry.class));
        }
        catch (Exception e)
        {
            LogHelper.error("Error connecting to sqlite: ");
            e.printStackTrace();
            sqliteconnection1 = null;
        }

        this.sqliteconnection = sqliteconnection1;
        this.query = VerifyHelper.verify(block.getEntryValue("query", StringConfigEntry.class), VerifyHelper.NOT_EMPTY, "Sqlite query can't be empty");
        /*
        this.queryParams = block.getEntry("queryParams", ListConfigEntry.class).stream(StringConfigEntry.class).toArray((x$0) -> {
            return new String[x$0];
        });
        */
        this.queryParams = block.getEntry("queryParams", ListConfigEntry.class).stream(StringConfigEntry.class).toArray(String[]::new);
    }

    public AuthProviderResult auth(String login, String password, String ip, String profile) throws SQLException, AuthException
    {
        Connection c = this.sqliteconnection;
        Throwable var5 = null;

        try
        {
            PreparedStatement s = c.prepareStatement(this.query);
            Throwable var7 = null;

            try
            {
                String[] replaceParams = new String[]{"login", login, "password", password, "ip", ip};

                for(int i = 0; i < this.queryParams.length; ++i)
                {
                    s.setString(i + 1, CommonHelper.replace(this.queryParams[i], replaceParams));
                }

                s.setQueryTimeout(MySQLSourceConfig.TIMEOUT);
                ResultSet set = s.executeQuery();
                Throwable var10 = null;

                try
                {
                    AuthProviderResult var55;
                    try
                    {
                        /*
                        AuthProviderResult var11 = set.next() ? new AuthProviderResult(set.getString(1), SecurityHelper.randomStringToken()) : authError("Incorrect username or password");
                        var55 = var11;
                        */

                        var55 = set.next() ? new AuthProviderResult(set.getString(1), SecurityHelper.randomStringToken()) : authError("Incorrect username or password");
                        return var55;
                        // return (AuthProviderResult)var55;
                    }
                    catch (Throwable var56)
                    {
                        //var55 = var56;
                        var10 = var56;
                        throw var56;
                    }
                }
                finally
                {
                    if (set != null)
                    {
                        if (var10 != null)
                        {
                            try
                            {
                                set.close();
                            }
                            catch (Throwable var55)
                            {
                                var10.addSuppressed(var55);
                            }
                        }
                        else
                        {
                            set.close();
                        }
                    }

                }
            }
            catch (Throwable var58)
            {
                var7 = var58;
                throw var58;
            }
            finally
            {
                if (s != null)
                {
                    if (var7 != null)
                    {
                        try
                        {
                            s.close();
                        }
                        catch (Throwable var54)
                        {
                            var7.addSuppressed(var54);
                        }
                    }
                    else
                    {
                        s.close();
                    }
                }
            }
        }
        catch (Throwable var60)
        {
            var5 = var60;
            throw var60;
        }
        finally
        {
            if (c != null)
            {
                if (var5 != null)
                {
                    try
                    {
                        c.close();
                    }
                    catch (Throwable var53)
                    {
                        var5.addSuppressed(var53);
                    }
                }
                else
                {
                    c.close();
                }
            }
        }
    }

    public void close()
    {
    }
}
