library(jwtRoutr)

context('JWT class')

claim <- jose::jwt_claim(user = "antoine", session_key = 123456, exp= unclass(Sys.time()+86000))
key <- charToRaw("SuperSecretKeyOfTheDeath")
jwt <- jose::jwt_encode_hmac(claim, secret = key)



test_that("creation of a JWT object", {

  jwt_auth = Jwt$new(key)

  expect_is(jwt_auth, 'Jwt')
  expect_is(jwt_auth, 'R6')
  expect_error(Jwt$new('bla'))
  expect_error(Jwt$new(key, decode_function = NULL))

})

jwt_auth = Jwt$new(key = key, auth_pattern = 'auth/*', decode_function = jose::jwt_decode_hmac)

route <- routr::Route$new()
route$add_handler('post', 'auth/', function(request, response, keys, ...) {
  jwt <- request$get_header('Jwt')
  response$status <- 200L
  response$type = 'application/json'
  response$body <- jsonlite::toJSON(jwt_auth$decode_jwt(jwt))
  TRUE
})

route$add_handler('post', 'noauth/', function(request, response, keys, ...) {
  jwt <- request$get_header('Jwt')
  response$status <- 200L
  response$type = 'application/json'
  response$body <- jsonlite::toJSON(jwt_auth$decode_jwt(jwt))
  TRUE
})

route$add_handler('post', '/', function(request, response, keys, ...) {
  response$status <- 200L
  response$body <- 'no authentication required'
  TRUE
})


router <- routr::RouteStack$new()
router$add_route(route, 'app_router')

app <- fiery::Fire$new('127.0.0.1', 9550)

app$attach(router)
app$attach(jwt_auth)


test_that('attach plugin to fiery/routr app', {
  expect_equal(sum('JWT' %in% names(app$plugins)), 1 )
  expect_equal(sum('header_routr' %in% names(app$plugins)),1 )
})

test_that('auth with good token', {
  request <- fiery::fake_request('127.0.0.1:9950/auth/', method = 'post', headers = list(jwt = jwt))
  res <- app$test_request(request)
  expect_equal(res$status, 200L)

  res <- jsonlite::fromJSON(res$body)
  expect_match(res$user, 'antoine')
})

test_that('auth with bad token', {
  request <- fiery::fake_request('127.0.0.1:9950/auth/', method = 'post', headers = list(jwt = 'bla.dlg.qqoe'))
  res <- app$test_request(request)

  expect_equal(res$status, 500L)

  request <- fiery::fake_request('127.0.0.1:9950/auth/', method = 'post')
  res <- app$test_request(request)

  expect_equal(res$status, 500L)

})

test_that('no auth', {
  request <- fiery::fake_request('127.0.0.1:9950/', method = 'post')
  res <- app$test_request(request)

  expect_equal(res$status, 200L)
  expect_match(res$body, 'no authentication required')
})

