#ifndef lol2_backend_H
#define lol2_backend_H

#if !defined(LOL2_FORCE_PORTABLE) && defined(__aarch64__) && \
    (defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES))
#    include "backend_neon.h" /* IWYU pragma: export */
#else
#    include "backend_portable.h" /* IWYU pragma: export */
#endif

#endif
