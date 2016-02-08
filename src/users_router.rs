extern crate iron;
extern crate router;

use self::iron::prelude::*;
use self::iron::status;

pub struct UserRouter;

impl UserRouter {
    fn not_implemented(_: &mut Request) -> IronResult<Response> {
        println!("Not implemented");
        Ok(Response::with(status::NotImplemented))
    }

    pub fn start(router: &mut router::Router) {
        router.post("/setup", UserRouter::not_implemented);

        router.post("/invitation", UserRouter::not_implemented);
        router.get("/invitation", UserRouter::not_implemented);
        router.delete("/invitation", UserRouter::not_implemented);

        router.post("/users", UserRouter::not_implemented);
        router.get("/users", UserRouter::not_implemented);
        router.put("/users/:id", UserRouter::not_implemented);
        router.post("/users/:id", UserRouter::not_implemented);

        router.post("/recoveries/:user", UserRouter::not_implemented);
        router.get("/recoveries/:user/:id", UserRouter::not_implemented);

        router.get("/permissions", UserRouter::not_implemented);
        router.get("/permissions/:user", UserRouter::not_implemented);
        router.get("/permissions/:user/:taxon", UserRouter::not_implemented);
        router.get("/permissions/_/:taxon", UserRouter::not_implemented);
        router.put("/permissions/:user/:taxon", UserRouter::not_implemented);
    }
}
