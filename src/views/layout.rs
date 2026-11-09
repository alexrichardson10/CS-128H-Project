use maud::{DOCTYPE, Markup, html};

pub fn base(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            html lang="en" {
                head {
                    meta charset="utf-8";
                    title { (title) }
                    link rel="stylesheet" href="/static/7.css";
                    meta name="viewport" content="width=device-width, intitial-scale=1";
                }
                body style="background-image: url('/static/images/home.png'); background-size: cover; background-position: center; height: 100vh; margin: 0;" {
                    // "navigation here"

                    main { (content) }

                    // footer here
                }
            }
        }
    }
}
