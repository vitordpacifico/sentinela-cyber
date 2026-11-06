"""Adaptador Tree-sitter para TypeScript e TSX (React Native, Expo, Angular, Node).

TypeScript é JavaScript com tipos. A gramática TSX gera a mesma AST do
JavaScript para expressões e chamadas, então este adaptador herda tudo do
``JavaScriptAdapter`` e só trata o que muda:

* parâmetros tipados (``required_parameter`` / ``optional_parameter``);
* expressões que só existem por causa dos tipos (``valor as string``,
  ``usuario!``, ``x satisfies T``): elas não mudam o dado, então a taint
  analysis atravessa esses nós normalmente.

As regras e as fontes/sinks de taint são as mesmas do JavaScript
(``rules_language = "javascript"``).
"""

from __future__ import annotations

from typing import Any

import tree_sitter_typescript
from tree_sitter import Node

from sentinela.engine.languages.base import Param
from sentinela.engine.languages.javascript import JavaScriptAdapter

# Nós de tipo que embrulham uma expressão sem alterar o valor.
_WRAPPERS = {"as_expression", "non_null_expression", "satisfies_expression", "type_assertion"}


class TypeScriptAdapter(JavaScriptAdapter):
    name = "typescript"
    rules_language = "javascript"
    extensions = (".ts", ".tsx", ".mts", ".cts")

    def _grammar(self) -> Any:
        # A gramática TSX aceita .ts e .tsx; só não aceita a coerção antiga ``<T>valor``.
        return tree_sitter_typescript.language_tsx()

    def function_params(self, node: Node) -> list[Param]:
        params = node.child_by_field_name("parameters")
        if params is None:
            return super().function_params(node)
        result: list[Param] = []
        for child in params.named_children:
            if child.type in {"required_parameter", "optional_parameter"}:
                pattern = child.child_by_field_name("pattern")
                type_node = child.child_by_field_name("type")
                type_name = self.text(type_node).lstrip(":").strip() if type_node is not None else None
                if pattern is None:
                    continue
                if pattern.type == "identifier":
                    result.append(Param(self.text(pattern), type_name=type_name))
                else:
                    result.extend(Param(name, type_name=type_name) for name in self._target_names(pattern))
            elif child.type == "identifier":
                result.append(Param(self.text(child)))
        return result

    def reference_name(self, node: Node) -> str | None:
        if node.type in _WRAPPERS and node.named_children:
            return self.reference_name(node.named_children[0])
        return super().reference_name(node)
