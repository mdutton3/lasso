void
DESTROY (SV *sv)
    CODE:
	GObject *object = gperl_get_object (sv);

        if (!object) /* Happens on object destruction. */
                return;
#ifdef NOISY
        warn ("DESTROY< (%p)[%d] => %s (%p)[%d]\n",
              object, object->ref_count,
              gperl_object_package_from_type (G_OBJECT_TYPE (object)),
              sv, SvREFCNT (SvRV(sv)));
#endif
        /* gobject object still exists, so take back the refcount we lend it. */
        /* this operation does NOT change the refcount of the combined object. */

	if (PL_in_clean_objs) {
                /* be careful during global destruction. basically,
                 * don't bother, since refcounting is no longer meaningful. */
                sv_unmagic (SvRV (sv), PERL_MAGIC_ext);

                g_object_steal_qdata (object, wrapper_quark);
        } else {
                SvREFCNT_inc (SvRV (sv));
                if (object->ref_count > 1) {
                    /* become undead */
                    SV *obj = SvRV(sv);
                    update_wrapper (object, MAKE_UNDEAD(obj));
                    /* printf("zombies! [%p] (%p)\n", object, obj);*/
                }
        }
        g_object_unref (object);
#ifdef NOISY
	warn ("DESTROY> (%p) done\n", object);
#endif

