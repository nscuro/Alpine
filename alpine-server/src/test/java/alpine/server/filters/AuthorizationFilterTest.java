/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.filters;

import alpine.Config;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.JsonWebToken;
import alpine.server.auth.PermissionRequired;
import alpine.server.persistence.PersistenceManagerFactory;
import alpine.server.resources.AlpineResource;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class AuthorizationFilterTest extends JerseyTest {

    @Path("/")
    public static class TestResource extends AlpineResource {

        @Context
        private ContainerRequestContext requestContext;

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        @PermissionRequired(value = {"FOO", "BAR"})
        @SuppressWarnings("unchecked")
        public Response get() {
            final var permissions = (Set<String>) requestContext.getProperty(
                    AuthorizationFilter.EFFECTIVE_PERMISSIONS_PROPERTY);
            return Response.ok(permissions).build();
        }

    }

    @BeforeAll
    static void setUpClass() {
        Config.enableUnitTests();
    }

    @AfterEach
    public void tearDown() throws Exception {
        PersistenceManagerFactory.tearDown();
        super.tearDown();
    }

    @Override
    protected Application configure() {
        return new ResourceConfig(TestResource.class)
                .register(AuthenticationFilter.class)
                .register(AuthorizationFilter.class);
    }

    @Test
    void shouldRejectRequestWithoutPermissions() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("foo");

            apiKey = qm.createApiKey(team).getClearTextKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldAllowRequestWithAtLeastOneRequiredPermission() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission permission = qm.createPermission("FOO", null);

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(permission);

            apiKey = qm.createApiKey(team).getClearTextKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.readEntity(String.class)).isEqualTo("[\"FOO\"]");
    }

    @Test
    void shouldAllowRequestWithAllRequiredPermissions() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission barPermission = qm.createPermission("BAR", null);

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);
            team.getPermissions().add(barPermission);

            apiKey = qm.createApiKey(team).getClearTextKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.readEntity(String.class)).isEqualTo("[\"BAR\",\"FOO\"]");
    }

    @Test
    void shouldAllowManagedUserRequestWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission permission = qm.createPermission("FOO", null);

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(permission);

            final ManagedUser managedUser = qm.createManagedUser("test", "test");
            managedUser.getTeams().add(team);

            bearerToken = new JsonWebToken().createToken(managedUser);
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.readEntity(String.class)).isEqualTo("[\"FOO\"]");
    }

    @Test
    void shouldAllowManagedUserRequestWithAtLeastOneRequiredPermission2() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission permission = qm.createPermission("FOO", null);

            final ManagedUser managedUser = qm.createManagedUser("test", "test");
            managedUser.getPermissions().add(permission);

            bearerToken = new JsonWebToken().createToken(managedUser);
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.readEntity(String.class)).isEqualTo("[\"FOO\"]");
    }

}