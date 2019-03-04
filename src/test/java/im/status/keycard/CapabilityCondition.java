package im.status.keycard;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.AnnotatedElement;
import java.util.HashSet;
import java.util.Optional;

import static org.junit.platform.commons.util.AnnotationUtils.findAnnotation;
import static org.junit.jupiter.api.extension.ConditionEvaluationResult.disabled;
import static org.junit.jupiter.api.extension.ConditionEvaluationResult.enabled;

public class CapabilityCondition implements ExecutionCondition {
  private static final ConditionEvaluationResult ENABLED_BY_DEFAULT = enabled("@Capabilities is not present");
  private static final ConditionEvaluationResult ENABLED = enabled("All capability requirements are satisfied");
  static HashSet<String> availableCapabilities;

  /**
   * Containers/tests are disabled if {@code @Disabled} is present on the test
   * class or method.
   */
  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
    Optional<AnnotatedElement> element = context.getElement();
    Optional<Capabilities> capsAnnotation = findAnnotation(element, Capabilities.class);

    if (capsAnnotation.isPresent()) {
      for (String c : capsAnnotation.get().value()) {
        if (!availableCapabilities.contains(c)) {
          return disabled("The " + c + " capability is not available on the tested target");
        }
      }

      return ENABLED;
    }

    return ENABLED_BY_DEFAULT;
  }
}
