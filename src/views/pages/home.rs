use crate::views::layout::base;
use maud::{Markup, html};

pub fn render() -> Markup {
    base(
        "Home",
        html! {
            div class="window active" style="position: absolute; top: 20px; left: 20px; width: calc(50% - 20px); height: calc(100% - 40px); display: flex; flex-direction: column;" {
                div class="title-bar" {
                    div class="title-bar-text" {
                        "This is a random stock image that I found on the web!"
                    }
                    div class="title-bar-controls" {
                        button aria-label="Minimize" disabled {}
                        button aria-label="Maximize" disabled {}
                        button aria-label="Close" {}
                    }
                }
                div class="window-body" style="flex: 1; overflow: hidden;" {
                    img src="/static/images/image01.png" style="width: 100%; height: 100%; object-fit: cover; object-position: center;";
                }
            }

            div style="position: absolute; top: 30%; left: 65%; height: 40%; width: 20%;" {
                div class="window" style="height: 75%; display: flex; flex-direction: column;" {
                    div class="window-body" style="flex: 1; overflow: hidden; margin-top: var(--w7-w-space);" {
                        img src="/static/images/user.png" alt="User picture"
                            style="width: 100%; height: 100%; object-fit: cover; display: block;";
                    }
                }

                div class="window active" style="margin-top: 5%; display: flex; flex-direction: column;" {
                    div class="title-bar" {
                        div class="title-bar-text" { "Log in" }
                        div class="title-bar-controls" {
                            button aria-label="Minimize" disabled {}
                            button aria-label="Maximize" disabled {}
                            button aria-label="Close" {}
                        }
                    }

                    div class="window-body" style="flex: 1" {
                        form method="post" action="/login" style="display: flex; flex-direction: column; gap: 10px; padding: 10px 10px;" {
                            div style="display: flex; justify-content: space-between; align-items: center;" {
                                label for="username" { "Username" }
                                input type="text" id="username" name="username";
                            }

                            div style="display: flex; justify-content: space-between; align-items: center;" {
                                label for="password" { "Password" }
                                input type="password" id="password" name="password";
                            }

                            button type="submit" style="align-self: center;" { "Log in" }
                        }
                    }
                }
            }
        },
    )
}
