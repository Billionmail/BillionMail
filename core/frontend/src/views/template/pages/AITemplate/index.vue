<template>
	<div class="wrapper">
		<div class="page-tit">
			<span class="tit-content">{{ $t('template.ai.title') }}</span>
		</div>

		<div class="ai-container">
			<div class="chat-area">
				<!-- <div class="model-select">
					<n-card>
						<div class="flex justify-start items-center gap-15px">
							<n-select v-model:value="currentModelTitle" class="flex-1" :options="modelList"
								label-field="title" value-field="title" @update:value="changeModel">
							</n-select>
						</div>
					</n-card>
				</div> -->

				<div ref="answerRef" class="answer" @wheel="handleScroll">
					<n-card class="h-100%">
						<n-scrollbar ref="chatScrollRef" style="height: calc(100vh - 415px)">
							<div v-if="chatRecord.size == 0" class="answer-container">
								<div class="ask-content">
									<div class="pic">
										<i
											class="i-material-symbols:account-circle text-6 text-[var(--color-primary-hover-1)]"></i>
									</div>
									<div class="text">
										{{ $t('template.ai.greeting') }}
									</div>
								</div>
							</div>
							<div ref="scrollWrapperRef">
								<template v-for="item in chatRecord" :key="item[0]">
									<div class="answer-container">
										<div class="ask-content">
											<div class="pic">
												<i
													class="i-material-symbols:account-circle text-6 text-[var(--color-primary-hover-1)]"></i>
											</div>
											<div class="text">
												{{ item[0].split('_+_')[0] }}
											</div>
										</div>
										<!-- <n-spin :description="$t('template.ai.loading.description')" :show="generateShow"> -->
										<div class="answer-content">
											<div class="pic">
												<span class="text-4 text-[var(--color-primary-hover-1)]">{{
													$t('template.ai.brandName')
												}}</span>
											</div>
											<div class="text">
												<MarkdownRender
													v-for="(_item, _index) in item[1]"
													:key="_index"
													:content="removeSignCode(_item)"
													:chat-record-key="item[0]"
													class="mb-4"
													@code-render="handleCodeRender">
												</MarkdownRender>
											</div>
											<div class="answer-tool">
												<div class="tool-item" @click="handleRegenerate(item[0].toString())">
													<i class="i-ri:refresh-line text-5"></i>
													<span>{{ $t('template.ai.buttons.regenerate') }}</span>
												</div>
												<n-popover trigger="hover">
													<template #trigger>
														<div class="tool-item">
															<i class="i-ri:information-2-fill text-5"></i>
															<span>{{ $t('template.ai.buttons.info') }}</span>
														</div>
													</template>
													<div
														v-if="usageRecord.get(item[0])"
														class="flex justify-start items-center gap-2.5">
														<div
															v-for="(info, info_key) in usageRecord.get(item[0])"
															:key="info_key">
															<span class="fw-bold">{{ info_key }}: </span>
															<span>{{ info }}</span>
														</div>
													</div>
												</n-popover>
											</div>
										</div>
										<!-- </n-spin> -->
									</div>
								</template>
							</div>
						</n-scrollbar>
					</n-card>
				</div>
				<div class="question">
					<n-card style="height: 100%">
						<n-input
							v-model:value="questionContent"
							type="textarea"
							:placeholder="$t('template.ai.welcomeMessage', { domain: chatInfo.domain })"
							class="question-input"
							@keydown.enter="e => sendChat(store, e)"></n-input>
						<div class="question-tools">
							<div class="flex justify-start gap-10px">
								<n-select
									v-model:value="currentModelTitle"
									:options="modelList"
									label-field="title"
									value-field="title"
									@update:value="changeModel">
								</n-select>
								<div class="flex justify-start items-center">
									<n-checkbox v-model:checked="useSpinTax" style="flex-shrink: 0">
										Spintax
									</n-checkbox>
									<n-input-number
										v-model:value="spinTaxLength"
										placeholder=""
										class="w-50px"
										:show-button="false"
										style="flex-shrink: 0"
										:disabled="!useSpinTax">
									</n-input-number>
								</div>
							</div>
							<div class="send-btn">
								<!-- <i
                                class="i-icon-park-twotone:new-picture text-8 text-[var(--color-primary-1)] hover-text-[var(--color-primary-hover-1)]"></i> -->
								<i
									v-if="!isChat"
									class="i-icon-park-twotone:arrow-circle-up text-8 text-[var(--color-primary-1)] hover-text-[var(--color-primary-hover-1)]"
									@click="sendChat(store)"></i>
								<i
									v-else
									class="i-svg-spinners:pulse-2 text-8 text-[var(--color-primary-1)] hover-text-[var(--color-primary-hover-1)]"
									@click="stopChat(store)"></i>
							</div>
						</div>
					</n-card>
				</div>
			</div>
			<div class="view-area">
				<n-card style="height: 100%">
					<div style="height: calc(100vh - 165px)">
						<div class="h-10 flex justify-between items-center gap-2.5 mb-5">
							<div class="flex justify-start items-center gap-2.5">
								<n-button-group size="small">
									<n-button
										:type="previewStatus == 'view' ? 'primary' : 'default'"
										@click="previewStatus = 'view'">
										<template #icon>
											<i class="i-mingcute:eye-2-fill text-5"></i>
										</template>
										{{ $t('template.ai.buttons.view') }}
									</n-button>
									<n-button
										:type="previewStatus == 'edit' ? 'primary' : 'default'"
										@click="previewStatus = 'edit'">
										<template #icon>
											<i class="i-tdesign:code text-5"></i>
										</template>
										{{ $t('template.ai.buttons.edit') }}
									</n-button>
								</n-button-group>
								<span v-if="previewStatus == 'edit'">{{
									$t('template.ai.tips.saveShortcut')
								}}</span>
							</div>
							<span class="text-4 fw-bold">{{ previewTit }}</span>
							<n-button
								style="width: 134px"
								type="primary"
								:disabled="!previewCode"
								@click="goToSendEmail">
								<template #icon>
									<i class="i-mingcute:mail-send-fill"></i>
								</template>
								{{ $t('template.ai.send') }}
							</n-button>
						</div>
						<n-scrollbar style="height: calc(100% - 40px)">
							<div v-if="previewStatus == 'view' && isChat" v-html="previewCode"></div>
							<iframe
								v-else-if="previewStatus == 'view' && !isChat"
								:srcdoc="previewCode"
								frameborder="0"
								class="w-100%"
								style="height: calc(100vh - 224px)"></iframe>
							<BtEditor
								v-else
								v-model:value="previewCode"
								style="height: calc(100vh - 217px)"
								@save="saveCodeChange(store)">
							</BtEditor>
						</n-scrollbar>
					</div>
				</n-card>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { useGlobalStore } from '@/store'
import {
	initialTemplateInfo,
	sendChat,
	removeHtmlCodeBlockMarkers,
	getHtmlTemplateContent,
	saveCodeChange,
	stopChat,
	removeSignCode,
	getContentFromTitleTags,
} from './controller'
import MarkdownRender from './components/MarkdownRender.vue'
import { useTemplateStore } from './store'
import { TemplateStore } from './dto'
import BtEditor from '@/components/base/bt-editor/index.vue'
const globalStore = useGlobalStore()
const router = useRouter()
const store = useTemplateStore()
provide<TemplateStore>('modelStore', store)
const {
	chatId,
	modelList,
	currentModelTitle,
	previewCode,
	questionContent,
	chatRecord,
	currentChatRecordKey,
	currentModel,
	isChat,
	chatScrollRef,
	scrollWrapperRef,
	scrollable,
	chatInfo,
	previewTit,
	usageRecord,
	useSpinTax,
	spinTaxLength,
} = store
const route = useRoute()

const previewStatus = ref('view')

chatId.value = route.params.chatId as string

/**
 * @description Handle model select
 */
function changeModel(_: string, options: any) {
	currentModel.value = options
}

/**
 * @description Get html template code content
 */
getHtmlTemplateContent(store)

/**
 * @description Initial chatInfo and modelList
 */
initialTemplateInfo(store)

/**
 * @description Render page code
 */
function handleCodeRender(data: { code: string; key: string }) {
	if (data.key == currentChatRecordKey.value) {
		previewCode.value = removeSignCode(removeHtmlCodeBlockMarkers(data.code))
		previewTit.value = getContentFromTitleTags(previewCode.value)
	}
}

/**
 * @description Regenerate
 */
function handleRegenerate(key: string) {
	questionContent.value = key.split('_+_')[0]
	sendChat(store)
}

/**
 * @description Listen scroll wrapper for height-change
 */
function scrollWrapperHeightChange(timer?: any, index = 0) {
	let timeoutTimer = timer || null
	let startIndex = index
	if (startIndex >= 6) {
		return
	}
	if (timeoutTimer) {
		clearTimeout(timer)
		timeoutTimer = null
	}
	if (scrollWrapperRef.value.offsetHeight) {
		chatScrollRef.value.scrollTo({ left: 0, top: scrollWrapperRef.value.offsetHeight })
		startIndex++
		return
	} else {
		startIndex++
		timeoutTimer = setTimeout(() => {
			scrollWrapperHeightChange(timeoutTimer, startIndex)
		}, 100)
	}
}
/**
 * @description If user scroll then stop n-scrollbar behavior
 */
function handleScroll(event: WheelEvent) {
	if (event.deltaY < 0) {
		scrollable.value = false
	}
}

/**
 * @description Go to send email
 */
async function goToSendEmail() {
	await saveCodeChange(store)
	globalStore.temp_subject = previewTit.value
	router.push({
		path: '/market/task/edit',
		query: {
			chat_id: chatInfo.value.chatId,
		},
	})
}

onMounted(() => {
	scrollWrapperHeightChange()
})
</script>

<style scoped lang="scss">
@use '@/styles/index' as base;
@use '../../mixin.scss';

.wrapper {
	width: 100% !important;

	@mixin content-card {
		border-radius: 5px;
		padding: 20px;
	}

	@include mixin.wrapper;

	.page-tit {
		@include mixin.page-tit;
	}

	.ai-container {
		width: 100%;
		display: grid;
		grid-template-columns: minmax(400px, 2fr) 5fr;
		gap: 15px;

		.chat-area {
			display: grid;
			grid-template-rows: 1fr 230px;
			gap: 15px;

			.answer {
				width: 100%;

				.answer-container {
					padding: 30px 10px;

					.ask-content,
					.answer-content {
						@include content-card();
						background: var(--color-bg-3);
						display: grid;
						grid-template-rows: 30px 1fr;
						gap: 10px;
						margin-bottom: 20px;

						.pic {
							@include base.row-flex;
							align-items: center;
						}

						@mixin item-tool {
							@include base.row-flex-start;
							cursor: pointer;
							gap: 5px;
							padding: 5px 10px;
							align-items: center;
							font-size: 12px;
							border-radius: 3px;
							transition: 0.1s all ease-in-out;

							&:hover {
								background: var(--color-primary-1);
								color: #fff;
							}

							&:active {
								background: var(--color-primary-3);
							}
						}

						.text {
							font-size: 14px;
						}

						.answer-tool {
							@include base.row-flex-end;
							border-top: 1px solid var(--color-border-1);
							height: 30px;
							padding-top: 20px;

							.tool-item {
								@include item-tool();
							}
						}
					}

					.answer-content {
						background: var(--color-bg-2);
					}
				}
			}

			.question {
				position: relative;

				.question-input {
					height: 100%;
					font-size: 14px;
				}

				.question-tools {
					position: absolute;
					padding: 5px 30px;
					@include base.row-flex;
					gap: 100px;
					bottom: 22px;
					left: 0;
					width: 100%;

					justify-content: space-between;

					.send-btn {
						@include base.row-flex-start;
						gap: 10px;

						i {
							cursor: pointer;
						}
					}
				}
			}
		}

		/* .view-area {
			background: linear-gradient(-45deg, rgba(238, 152, 82, 0.3),rgba(35, 166, 213,.3), rgba(231, 60, 60, 0.3),  rgba(35, 213, 171,.3));
                background-size: 400% 400%;
                animation: gradient 15s ease infinite;

                @keyframes gradient {
                    0% {
                        background-position: 0% 50%;
                    }

                    50% {
                        background-position: 100% 50%;
                    }

                    100% {
                        background-position: 0% 50%;
                    }
                } 
		} */
	}
}
</style>
