<template>
    <div class="max-w-4xl mx-auto px-4 py-8">
        <n-card class="mb-5">
            <div class="page-tit" style="margin: 0;">
                <div class="left-tit">
                    <div class="back-tool">
                        <i class="i-ri:apps-fill text-6"></i>
                    </div>
                    <span class="tit-content">
                        AI Model
                    </span>
                </div>
            </div>
        </n-card>

        <n-card>
            <!-- Model maneger modal -->
            <ModelManager  />
        </n-card>
    </div>


</template>

<script setup lang="tsx">
    import ModelManager from './components/ModelManager.vue';
    import { ModelStore } from './dto';
    import { useModelManagerStore } from './store/index,';
    const modelManagerStore = useModelManagerStore()
    provide<ModelStore>("modelStore", modelManagerStore)

</script>

<style scoped lang="scss">
    @use "@/styles/index.scss" as base;
    @use "@/views/domain/pages/editDomain/components/mixin.scss";

    .page-tit {
        @include mixin.page-tit;
    }

    .model-item {
        .item-header {
            @include base.row-flex;
            justify-content: space-between;

            .header-left {
                @include base.row-flex-start;
                gap: 10px;

                .model-tit {
                    font-size: 16px;
                    font-weight: bold;
                }
            }

            .header-right {
                .remove-model {
                    padding: 5px;
                    cursor: pointer;
                    @include base.row-flex-center;
                    transition: .15s all ease-in-out;

                    &:hover {
                        background: var(--color-bg-4)
                    }
                }
            }
        }

        .item-desc {
            @include base.row-flex-start;
            gap: 15px;

            .label {
                font-weight: bold;
            }
        }
    }
</style>