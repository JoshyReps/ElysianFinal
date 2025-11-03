$(function () {
    const $navbar = $(".nav-bar");
    const $header = $("#header");
    let ticking = false;
    let firstClick = true;

    window.addEventListener("scroll", () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const scrolled = window.scrollY > 50;
                $navbar.toggleClass("nav-bar-scrolled", scrolled)
                    .toggleClass("nav-bar-top", !scrolled);
                $header.toggleClass("header-scrolled", scrolled)
                    .toggleClass("header-top", !scrolled);
                ticking = false;
            });
            ticking = true;
        }
    });

    $(window).on("load", function () {
        $(".loader-wrapper").fadeOut(300);
    });

    if ($(".mySwiper").length) {
        new Swiper(".mySwiper", {
            slidesPerView: 1,
            loop: false,
            pagination: {
                el: ".banner-pagination",
                type: "fraction",
            },
            autoplay: {
                delay: 2500,
                disableOnInteraction: false,
                pauseOnMouseEnter: true,
            },
            effect: "slide",
            speed: 600,
            lazy: {
                loadPrevNext: true,
                loadOnTransitionStart: true,
            },
            preloadImages: false,
        });
    }

    if ($(".cakeSwiper").length) {
        new Swiper(".cakeSwiper", {
            loop: false,
            grabCursor: true,
            spaceBetween: 20,
            speed: 500,
            pagination: {
                el: ".cake-pagination",
                clickable: true,
                dynamicBullets: true,
            },
            navigation: {
                nextEl: ".cake-next",
                prevEl: ".cake-prev",
            },
            lazy: {
                loadPrevNext: true,
                loadPrevNextAmount: 2,
            },
            preloadImages: false,
            breakpoints: {
                0: { slidesPerView: 1 },
                620: { slidesPerView: 2 },
                1024: { slidesPerView: 3 },
            },
        });
    }

    const $countDiv = $(".order-amount");
    let countOrder = 0;

    window.order = function (count) {
        countOrder = firstClick ? ++count : ++countOrder;
        $countDiv.text(countOrder);
        firstClick = false;

        $countDiv.stop(true, true)
            .addClass("pop")
            .delay(200)
            .queue(function (next) {
                $(this).removeClass("pop");
                next();
            });
    };
});



const trendSwiper = new Swiper(".trendSwiper", {
    slidesPerView: 3,
    spaceBetween: 30,
    loop: true,
    centeredSlides: true,
    pagination: {
        el: ".trend-pagination",
        clickable: true,
    },
    navigation: {
        nextEl: ".trend-next",
        prevEl: ".trend-prev",
    },
    breakpoints: {
        0: {
            slidesPerView: 1,
        },
        650: {
            slidesPerView: 2,
        },
        1024: {
            slidesPerView: 3,
        },
    },
});
