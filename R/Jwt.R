#' Jwt Class
#' @export
Jwt <- R6::R6Class('Jwt',
               public = list(
                 decode_function = NULL,
                 initialize = function(key,auth_pattern = '*', decode_function = jose::jwt_decode_hmac) {

                   assertthat::assert_that(class(key) == 'raw')
                   assertthat::assert_that(class(decode_function) == 'function')

                   private$key = key
                   self$decode_function = decode_function
                   private$auth_pattern = auth_pattern
                 },
                 name = 'JWT',
                 on_attach = function(server, ...) {

                   if (!server$has_plugin('header_routr')) {
                     router <- routr::RouteStack$new()
                     router$attach_to <- private$attach_to
                     server$attach(router)
                   }

                   router  <- server$plugins$header_routr
                   auth_route <- self$auth_route_function()
                   router$add_route(auth_route, 'auth')

                 },
                 auth_route_function = function(type = 'jwt') {
                   route <- routr::Route$new()
                   route$add_handler('all', private$auth_pattern, function(request, response, keys, ...) {

                     req_auth <- request$get_header('Jwt')

                     if (is.null(req_auth) ) {
                       response$status_with_text(401L)
                       FALSE
                     }  else if (class(self$check_jwt(req_auth))[1] != 'jwt_claim')  {
                       response$status_with_text(401L)
                       FALSE
                     } else {
                       TRUE
                     }
                   })
                   route
                 },
                 check_jwt = function (jwt) {

                   claim <- tryCatch(self$decode_function(jwt, secret = private$key), error = function(e) {print(e); e})

                   if ('error' %in% class(claim)) {
                     return(FALSE)
                   } else if (is.null(claim$exp) | (unclass(Sys.time()) > claim$exp)) {
                     return(FALSE)
                   } else {
                     return(claim)
                   }

                 },

                 decode_jwt = function(jwt) {
                   self$decode_function(jwt, secret = private$key)
                 }

               ), private = list(
                 key = NULL,
                 attach_to = 'header',
                 auth_pattern = NULL
               ))
