/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public class CatalogAccessControlRule
{
    private final boolean allow;
    private final Optional<Pattern> userRegex;
    private final Optional<Pattern> catalogRegex;
    private final List<Pattern> userPatterns;

    @JsonCreator
    public CatalogAccessControlRule(
            @JsonProperty("allow") boolean allow,
            @JsonProperty("user") Optional<Pattern> userRegex,
            @JsonProperty("catalog") Optional<Pattern> catalogRegex,
            @JsonProperty("user_patterns") Optional<List<Pattern>> userPatterns)
    {
        this.allow = allow;
        this.userRegex = requireNonNull(userRegex, "userRegex is null");
        this.catalogRegex = requireNonNull(catalogRegex, "catalogRegex is null");
        this.userPatterns = userPatterns.map(ImmutableList::copyOf).orElse(ImmutableList.of());
    }

    public Optional<Boolean> match(String user, String catalog)
    {
        if (userRegex.map(regex -> regex.matcher(user).matches()).orElse(true) &&
                catalogRegex.map(regex -> regex.matcher(catalog).matches()).orElse(true)) {
            return Optional.of(allow);
        }
        return Optional.empty();
    }

    public boolean matchPrincipal(Principal principal, String userName)
    {
        if (userPatterns.isEmpty()) {
            return true;
        }

        if (principal == null) {
            return false;
        }

        String principalName = principal.getName();

        for (Pattern pattern : userPatterns) {
            Matcher matcher = pattern.matcher(principalName);
            while (matcher.matches()) {
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    String extractedUsername = matcher.group(i);
                    if (userName.equals(extractedUsername)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
