export namespace backend {
	
	export class FrontendResponse {
	    result: boolean;
	    msg: string;
	
	    static createFrom(source: any = {}) {
	        return new FrontendResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.result = source["result"];
	        this.msg = source["msg"];
	    }
	}
	export class LogInfo {
	    info: string;
	    level: number;
	
	    static createFrom(source: any = {}) {
	        return new LogInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.info = source["info"];
	        this.level = source["level"];
	    }
	}

}

