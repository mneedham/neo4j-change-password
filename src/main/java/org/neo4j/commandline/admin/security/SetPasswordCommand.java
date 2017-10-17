/*
 * Copyright (c) 2002-2016 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Neo4j is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.neo4j.commandline.admin.security;

import java.io.File;
import java.nio.file.Path;
import java.util.Optional;

import org.neo4j.commandline.admin.AdminCommand;
import org.neo4j.commandline.admin.AdminCommandSection;
import org.neo4j.commandline.admin.CommandFailed;
import org.neo4j.commandline.admin.IncorrectUsage;
import org.neo4j.commandline.admin.OutsideWorld;
import org.neo4j.commandline.arguments.Arguments;
import org.neo4j.helpers.Args;
import org.neo4j.kernel.configuration.Config;
import org.neo4j.logging.NullLogProvider;
import org.neo4j.server.configuration.ConfigLoader;
import org.neo4j.server.security.auth.CommunitySecurityModule;
import org.neo4j.kernel.impl.security.Credential;
import org.neo4j.server.security.auth.FileUserRepository;
import org.neo4j.kernel.impl.security.User;

import static org.neo4j.kernel.api.security.UserManager.INITIAL_USER_NAME;

public class SetPasswordCommand implements AdminCommand
{
    public static class Provider extends AdminCommand.Provider
    {

        public Provider()
        {
            super( "set-password" );
        }


        @Override
        public Arguments allArguments()
        {
            return new Arguments()
                    .withMandatoryPositionalArgument(0, "user")
                    .withMandatoryPositionalArgument(1, "password");
        }

        @Override
        public String summary()
        {
            return "Sets the password of the admin user ('" + INITIAL_USER_NAME + "').";
        }

        @Override
        public AdminCommandSection commandSection()
        {
            return AuthenticationCommandSection.instance();
        }

        @Override
        public String description()
        {
            return "Sets the initial (admin) user.";
        }

        @Override
        public AdminCommand create( Path homeDir, Path configDir, OutsideWorld outsideWorld )
        {
            return new SetPasswordCommand( homeDir, configDir, outsideWorld );
        }
    }

    final Path homeDir;
    final Path configDir;
    OutsideWorld outsideWorld;

    public SetPasswordCommand( Path homeDir, Path configDir, OutsideWorld outsideWorld )
    {
        this.homeDir = homeDir;
        this.configDir = configDir;
        this.outsideWorld = outsideWorld;
    }

    @Override
    public void execute( String[] args ) throws IncorrectUsage, CommandFailed
    {
        Args parsedArgs = Args.withFlags( "force", "requires-password-change" ).parse( args );

        String username = parsedArgs.orphans().size() > 0 ? parsedArgs.orphans().get( 0 ) : null;
        String password = parsedArgs.orphans().size() > 1 ? parsedArgs.orphans().get( 1 ) : null;
        boolean requiresPasswordChange = parsedArgs.getBoolean( "requires-password-change", true );
        boolean force = parsedArgs.getBoolean( "force" );

        try
        {
            if ( username == null || password == null )
            {
                throw new IncorrectUsage(
                        "Missing arguments: 'set-password' expects username and password arguments" );
            }
            setPassword( username, password, requiresPasswordChange, force );
        }

        catch ( Exception e )
        {
            throw new CommandFailed( "Failed run 'set-password' on '" + username + "': " + e.getMessage(), e );
        }
        catch ( Throwable t )
        {
            throw new CommandFailed( "Failed run 'set-password' on '" + username + "': " + t.getMessage(),
                    new RuntimeException( t.getMessage() ) );
        }
    }

    private void setPassword( String username, String password, boolean requirePasswordChange, boolean force )
            throws Throwable
    {
        Config config = loadNeo4jConfig();
        File file = CommunitySecurityModule.getInitialUserRepositoryFile( config );
        if ( outsideWorld.fileSystem().fileExists( file ) )
        {
            if ( force )
            {
                outsideWorld.fileSystem().deleteFile( file );
            }
            else
            {
                throw new IncorrectUsage( "Initial user already set. Overwrite this user with --force" );
            }
        }

        FileUserRepository userRepository =
                new FileUserRepository( outsideWorld.fileSystem(), file, NullLogProvider.getInstance() );
        userRepository.start();
        userRepository.create(
                new User.Builder( username, Credential.forPassword( password ) )
                        .withRequiredPasswordChange( requirePasswordChange )
                        .build()
        );
        userRepository.shutdown();
        outsideWorld.stdOutLine( "Changed password for user '" + username + "'" );
    }

    private Config loadNeo4jConfig()
    {
        ConfigLoader configLoader = new ConfigLoader();
        return configLoader.loadConfig(
                Optional.of( homeDir.toFile() ),
                Optional.of( configDir.resolve( "neo4j.conf" ).toFile() ) );
    }

}
