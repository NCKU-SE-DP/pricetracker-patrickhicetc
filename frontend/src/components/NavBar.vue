<template>
    <nav class="navbar">
        <div class="Title">
            <div class="title"> <RouterLink to="/overview">價格追蹤小幫手</RouterLink></div>
            <button class="hamburger" @click="isclickham">{{ (hamburger ? "X":"&#9776;") }}</button>
        </div>
        <ul class="options" v-if="hamburger||!isscreensmall">
            <li><RouterLink to="/overview">物價概覽</RouterLink></li>
            <li><RouterLink to="/trending">物價趨勢</RouterLink></li>
            <li><RouterLink to="/news">相關新聞</RouterLink></li>
            <li v-if="!isLoggedIn"><RouterLink to="/login">登入</RouterLink></li>
            <li v-else @click="logout">Hi, {{getUserName}}! 登出</li>
        </ul>
    </nav>
</template>

<script>
import { useAuthStore } from '@/stores/auth';

export default {
    name: 'NavBar',
    data(){
        return{
            hamburger: false,
            windowwidth: window.innerWidth
        }
    },
    computed: {
        isscreensmall(){
            return this.windowwidth < 768;
        },
        isLoggedIn(){
            const userStore = useAuthStore();
            return userStore.isLoggedIn;
        },
        getUserName(){
            const userStore = useAuthStore();
            return userStore.getUserName;
        }
    },
    mounted() {
        window.addEventListener('resize', this.handleResize);
        this.handleResize();
    },
    beforeUnmount() {
        window.removeEventListener('resize', this.handleResize);
    },
    methods: {
        handleResize(){
            this.windowwidth = window.innerWidth;
            this.hamburger = this.windowwidth >= 768;
        },
        isclickham(){
            this.hamburger = !this.hamburger;
        },
        logout(){
            const userStore = useAuthStore();
            userStore.logout();
        }
    }
};
</script>

<style scoped>
.navbar {
    display: flex;
    justify-content: space-between;
    background-color: #f3f3f3;
    padding: 1.5em;
    height: 4.5em;
    width: 100%;
    align-items: center;
    box-shadow: 0 0 5px #000000;
}

.navbar ul {
    list-style: none;
    display: flex;
    justify-content: space-around;
}

.title > a{
    font-size: 1.4em;
    font-weight: bold;
    color: #2c3e50 !important;
}

.navbar li {
    color: #aeb3b6;
    margin: 0 .5em;
    font-size: 1.2em;
}

.navbar li:hover{
    cursor: pointer;
    font-weight: bold;
}

.navbar a {
    text-decoration: none;
    color: #575B5D;
}
.hamburger {
    display: none;
    font-size: 24px;
    cursor: pointer;
}
.Title{
    display: flex;
    justify-content: space-between;
    align-items: center;
}
@media (max-width: 768px) {
    .navbar{
        flex-direction: column;
        align-items: flex-start;
        width: 100%;
        padding: 0;
    }
    .navbar li{
        border-bottom: 1px solid #cabebe;
    }
    .options{
        flex-direction: column;
        width: 100%;
        gap: 10px;
        text-align: center;
        padding: 5px;
        background-color: #e6ddf1;
    }
    .hamburger {
        display: block;
    }
    .Title{
        width: 100%;
        padding: 18px;
    }
}
</style>