<template>
    <div class="wrapper">
        <!-- Page tit -->
        <div class="page-tit">
            <span class="tit-content">
                Template
            </span>
        </div>

        <!-- Content  -->
        <div class="container">
            <div class="container-top">
                <n-button type="primary" @click="handleCreateTpl">Create Template</n-button>
            </div>
        </div>
    </div>

    <CreateTplModal ref="createTplModalRef"/>
</template>

<script setup lang="ts">
import CreateTplModal from './components/CreateTplModal.vue'
const createTplModalRef = ref()
/**
 * @description open creation modal when click button
 */
function handleCreateTpl(){
    createTplModalRef.value.open()
}
</script>

<style scoped lang="scss">
@use "@/styles/index" as base;
@use "./mixin.scss";

.wrapper {
    @include mixin.wrapper;

    .page-tit {
        @include mixin.page-tit;
    }
}
</style>