============================
Implantation du mapping Java
============================

:author: Benjamin Poussin <poussin@codelutin.com>

La même hierarchie d'objet à été faite dans la mesure du possible entre
l'implantation C et Java.

Conservation de l'objet C associé à l'objet Java
================================================

Chaque objet Java hérite d'un objet LassoNode qui contient un champs
*long c_lasso_object* qui permet de stocker la référence du pointer de
l'objet C associé à cet objet Java.

Destruction des objets
======================

L'objet LassoNode contient aussi une méthode finalize qui permet l'appel au
destructeur de l'objet C, lorsque l'objet java est libéré.

Si une méthode destroy particulière doit-être utilisé pour un objet C, il
suffit dans l'objet Java de redéfinir la méthode
*native protected void destroy();* et de l'implanter différement dans
l'implantation C de la méthode native.

Acces au attribut des objets C
==============================

Chaque attribut des objets C est accessible par une méthode d'acces. Cette
méthode se charge de demander la construction de l'objet de représentation
Java du champs. Ceci est fait par une méthode *init<FieldName>Field*. Cette
méthode ne modifie l'attribut que si l'objet C et l'objet Java ne sont plus
synchronisé, c'est à dire si la valeur dans l'objet C à été modifié ou que
l'objet Java la représentant n'a jamais été créer.

