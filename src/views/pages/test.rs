use maud::{DOCTYPE, Markup, html};

pub fn render() -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                title { "Test" }
            }
            body {
                form method="post" action="/login" {
                    fieldset {
                        legend { "Log in" }

                        label for="username" { "Username" }
                        br;
                        input type="text" id="username" name="username";
                        br;
                        br;

                        label for="password" { "Password" }
                        br;
                        input type="password" id="password" name="password";
                        br;
                        br;

                        button type="submit" { "Log in" }
                    }
                }
            }
        }
    }
}
