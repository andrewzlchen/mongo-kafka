/*
 * Copyright 2008-present MongoDB, Inc.
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
 */

package com.mongodb.kafka.connect.util;

import static com.mongodb.kafka.connect.util.ConfigHelper.getConfigByName;
import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Locale.ROOT;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.Config;
import org.apache.kafka.common.config.types.Password;

public final class ConnectionUriBlocklist {

  public static final String BLOCKED_OPTIONS_PROPERTY =
      "mongodb.kafka.connect.connection.uri.blocked.options";
  public static final String BLOCKED_OPTIONS_ENV_VAR =
      "MONGODB_KAFKA_CONNECT_CONNECTION_URI_BLOCKED_OPTIONS";
  public static final String BLOCKED_AUTH_MECHANISMS_PROPERTY =
      "mongodb.kafka.connect.connection.uri.blocked.auth.mechanisms";
  public static final String BLOCKED_AUTH_MECHANISMS_ENV_VAR =
      "MONGODB_KAFKA_CONNECT_CONNECTION_URI_BLOCKED_AUTH_MECHANISMS";
  public static final String ALLOW_HOST_CREDENTIALS_PROPERTY =
      "mongodb.kafka.connect.connection.uri.allow.host.credentials";
  public static final String ALLOW_HOST_CREDENTIALS_ENV_VAR =
      "MONGODB_KAFKA_CONNECT_CONNECTION_URI_ALLOW_HOST_CREDENTIALS";

  public static final List<String> DEFAULT_BLOCKED_OPTIONS =
      unmodifiableList(asList("tlsCertificateKeyFile", "tlsCertificateKeyFilePassword"));
  public static final List<String> DEFAULT_BLOCKED_AUTH_MECHANISMS =
      unmodifiableList(asList("MONGODB-AWS", "MONGODB-OIDC", "GSSAPI", "MONGODB-X509"));

  private static final String CONNECTION_URI_CONFIG = "connection.uri";

  private static final String AMBIENT_MECHANISM_PROBLEM =
      "The '%s' authentication mechanism is blocked. An administrator can set the '%s' Connect "
          + "worker setting to true to allow it.";
  private static final String BLOCKED_AUTH_MECHANISM_PROBLEM =
      "The '%s' authentication mechanism is blocked by the '%s' Connect worker setting. An "
          + "administrator can remove it from that setting to allow it.";
  private static final String BLOCKED_OPTION_PROBLEM =
      "The %s connection URI option is blocked by the '%s' Connect worker setting. An "
          + "administrator can change that setting to allow it.";
  private static final String BLOCKED_OPTIONS_PROBLEM =
      "The %s connection URI options are blocked by the '%s' Connect worker setting. An "
          + "administrator can change that setting to allow them.";

  public static boolean validate(final AbstractConfig connectorConfig, final Config config) {
    String connectionString = connectorConfig.getPassword(CONNECTION_URI_CONFIG).value();
    return addErrorMessagesIfInvalid(connectionString, config);
  }

  public static boolean validate(
      final Map<String, String> connectorProperties, final Config config) {
    String connectionString = connectorProperties.getOrDefault(CONNECTION_URI_CONFIG, "");
    return addErrorMessagesIfInvalid(connectionString, config);
  }

  public static void validateConnectionStringOptions(
      final String configName, final String connectionString) {
    List<String> problems = findProblems(connectionString, blockedOptions());
    if (!problems.isEmpty()) {
      throw new ConnectConfigException(configName, Password.HIDDEN, String.join(" ", problems));
    }
  }

  static List<String> blockedOptions() {
    String value = setting(BLOCKED_OPTIONS_PROPERTY, BLOCKED_OPTIONS_ENV_VAR);
    return value != null ? parseBlocklist(value) : DEFAULT_BLOCKED_OPTIONS;
  }

  static List<String> blockedAuthMechanisms() {
    String value = setting(BLOCKED_AUTH_MECHANISMS_PROPERTY, BLOCKED_AUTH_MECHANISMS_ENV_VAR);
    if (value != null) {
      return parseBlocklist(value);
    }
    return allowHostCredentials() ? emptyList() : DEFAULT_BLOCKED_AUTH_MECHANISMS;
  }

  /**
   * Whether the worker administrator allows authentication mechanisms that use host credentials.
   */
  static boolean allowHostCredentials() {
    String value = setting(ALLOW_HOST_CREDENTIALS_PROPERTY, ALLOW_HOST_CREDENTIALS_ENV_VAR);
    return value != null && Boolean.parseBoolean(value.trim());
  }

  private static String setting(final String systemProperty, final String environmentVariable) {
    String value = System.getProperty(systemProperty);
    return value != null ? value : System.getenv(environmentVariable);
  }

  static List<String> parseBlocklist(final String listValue) {
    if (listValue == null) {
      return emptyList();
    }
    return Arrays.stream(listValue.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());
  }

  private static boolean addErrorMessagesIfInvalid(
      final String connectionString, final Config config) {
    List<String> problems = findProblems(connectionString, blockedOptions());
    if (problems.isEmpty()) {
      return false;
    }
    String errorMessage = String.join(" ", problems);
    getConfigByName(config, CONNECTION_URI_CONFIG)
        .filter(
            connectionUriConfigValue ->
                !connectionUriConfigValue.errorMessages().contains(errorMessage))
        .ifPresent(
            connectionUriConfigValue -> connectionUriConfigValue.addErrorMessage(errorMessage));
    return true;
  }

  private static List<String> findProblems(
      final String connectionString, final List<String> blocklist) {
    List<String> problems = new ArrayList<>();
    String authMechanismProblem = findBlockedAuthMechanismProblem(connectionString);
    if (authMechanismProblem != null) {
      problems.add(authMechanismProblem);
    }
    Set<String> blockedOptions = findBlockedOptions(connectionString, blocklist);
    if (!blockedOptions.isEmpty()) {
      problems.add(
          format(
              blockedOptions.size() == 1 ? BLOCKED_OPTION_PROBLEM : BLOCKED_OPTIONS_PROBLEM,
              joinOptions(blockedOptions),
              BLOCKED_OPTIONS_PROPERTY));
    }
    return problems;
  }

  private static String joinOptions(final Set<String> options) {
    List<String> quotedOptions =
        options.stream().map(o -> "'" + o + "'").collect(Collectors.toList());
    if (quotedOptions.size() == 1) {
      return quotedOptions.get(0);
    }
    return String.join(", ", quotedOptions.subList(0, quotedOptions.size() - 1))
        + " and "
        + quotedOptions.get(quotedOptions.size() - 1);
  }

  static String findBlockedAuthMechanismProblem(final String connectionString) {
    if (!isBlockedAuthMechanismsConfigured()) {
      return findAmbientMechanismProblem(connectionString, allowHostCredentials());
    }
    Set<String> blockedMechanisms =
        findBlockedAuthMechanisms(connectionString, blockedAuthMechanisms());
    return blockedMechanisms.isEmpty()
        ? null
        : format(
            BLOCKED_AUTH_MECHANISM_PROBLEM,
            blockedMechanisms.iterator().next(),
            BLOCKED_AUTH_MECHANISMS_PROPERTY);
  }

  private static boolean isBlockedAuthMechanismsConfigured() {
    return setting(BLOCKED_AUTH_MECHANISMS_PROPERTY, BLOCKED_AUTH_MECHANISMS_ENV_VAR) != null;
  }

  static String findAmbientMechanismProblem(
      final String connectionString, final boolean allowHostCredentials) {
    if (allowHostCredentials) {
      return null;
    }
    Set<String> blockedMechanisms =
        findBlockedAuthMechanisms(connectionString, DEFAULT_BLOCKED_AUTH_MECHANISMS);
    return blockedMechanisms.isEmpty()
        ? null
        : format(
            AMBIENT_MECHANISM_PROBLEM,
            blockedMechanisms.iterator().next(),
            ALLOW_HOST_CREDENTIALS_PROPERTY);
  }

  static Set<String> findBlockedAuthMechanisms(
      final String connectionString, final List<String> blocklist) {
    Set<String> blockedMechanisms = new LinkedHashSet<>();
    if (blocklist.isEmpty() || connectionString == null) {
      return blockedMechanisms;
    }
    String authMechanism = getOption(connectionString, "authMechanism");
    if (authMechanism == null) {
      return blockedMechanisms;
    }
    String normalisedMechanism = authMechanism.trim().toUpperCase(ROOT);
    for (String blockedMechanism : blocklist) {
      if (blockedMechanism.trim().toUpperCase(ROOT).equals(normalisedMechanism)) {
        blockedMechanisms.add(normalisedMechanism);
        break;
      }
    }
    return blockedMechanisms;
  }

  static Set<String> findBlockedOptions(
      final String connectionString, final List<String> blocklist) {
    if (blocklist.isEmpty() || connectionString == null) {
      return new LinkedHashSet<>();
    }
    int queryStart = connectionString.indexOf('?');
    if (queryStart < 0) {
      return new LinkedHashSet<>();
    }
    Set<String> normalisedBlocklist = new HashSet<>();
    for (String blockedOption : blocklist) {
      String trimmed = blockedOption.trim();
      normalisedBlocklist.add(trimmed.toLowerCase(Locale.ROOT));
      normalisedBlocklist.add(trimmed.toLowerCase());
    }
    Set<String> blockedOptions = new LinkedHashSet<>();
    Set<String> seenOptions = new LinkedHashSet<>();
    for (String option : connectionString.substring(queryStart + 1).split("&|;")) {
      int valueStart = option.indexOf('=');
      String optionName = valueStart >= 0 ? option.substring(0, valueStart) : option;
      String rootName = optionName.toLowerCase(Locale.ROOT);
      String driverName = optionName.toLowerCase();
      if (!optionName.isEmpty()
          && (normalisedBlocklist.contains(rootName) || normalisedBlocklist.contains(driverName))
          && seenOptions.add(driverName)) {
        // Preserve the option name as written in the connection string for the error message
        blockedOptions.add(optionName);
      }
    }
    return blockedOptions;
  }

  static String getOption(final String connectionString, final String optionName) {
    int queryStart = connectionString.indexOf('?');
    if (queryStart < 0) {
      return null;
    }
    String lowerCaseOptionName = optionName.toLowerCase(ROOT);
    String value = null;
    for (String option : connectionString.substring(queryStart + 1).split("&|;")) {
      int valueStart = option.indexOf('=');
      String name = valueStart >= 0 ? option.substring(0, valueStart) : option;
      if (name.toLowerCase(ROOT).equals(lowerCaseOptionName)
          || name.toLowerCase().equals(lowerCaseOptionName)) {
        value = valueStart >= 0 ? decodeOptionValue(option.substring(valueStart + 1)) : "";
      }
    }
    return value;
  }

  /** Decodes option values the same way the driver does. */
  private static String decodeOptionValue(final String value) {
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
    } catch (Exception e) {
      return value;
    }
  }

  private ConnectionUriBlocklist() {}
}
