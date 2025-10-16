import type { LineSeriesOption } from 'echarts/charts'
import type {
	TooltipComponentOption,
	GridComponentOption,
	DataZoomComponentOption,
	GraphicComponentOption,
} from 'echarts/components'
import type { ComposeOption } from 'echarts/core'

export type ECOptionLine = ComposeOption<
	| LineSeriesOption
	| TooltipComponentOption
	| GridComponentOption
	| DataZoomComponentOption
	| GraphicComponentOption
>
