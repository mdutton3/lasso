================
JNI for dummy :)
================

Sous Linux le nom de la librairie compilée doit obligatoirement commencer par **lib** et
finir par **.so**.

Pour charger à l'éxécution la librairie elle doit-être dans le
LD_LIBRAIRY_PATH et en Java il faut la charger avec **System.loadLibrary**::

Par exemple si vous avec généré la librairie libjlasso.so, on la chargera
avec::

  System.loadLibrary("jlasso");

Pour connaitre le nom de la librairie que le système attend, on peut
utiliser::

  System.out.println(System.mapLibraryName("jlasso"));

Comment ajouter des fonctions JNI
=================================

:ref: http://java.sun.com/docs/books/jni/html/jniTOC.html
:ref: http://gbm.esil.univ-mrs.fr/~tourai/Java/node48.html

Il faut créer les classes Java, et marquer les méthodes qui doivent être
écrite en C, avec le mot cle native. Ces méthodes n'ont pas de corps en
Java.

Il faut ensuite exécuter le Makefile se trouvant dans lasso/java pour qu'il
génère les fichiers d'entête JNI. 

Il ne reste plus qu'a reprendre la signature de la méthode et de la coder
dans le .c

