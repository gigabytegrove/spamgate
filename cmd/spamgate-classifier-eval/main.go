// spamgate-classifier-eval evaluates labeled offline corpora without altering live mail.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "strings"

 "github.com/gigabytegrove/spamgate/internal/qualification"
)
func run(args []string,in io.Reader,out io.Writer) error {
 flags:=flag.NewFlagSet("spamgate-classifier-eval",flag.ContinueOnError)
 flags.SetOutput(io.Discard)
 threshold:=flags.Float64("threshold",5,"score at or above this value is classified as spam")
 if err:=flags.Parse(args);err!=nil{return err}
 if flags.NArg()!=0{return errors.New("unexpected positional arguments")}
 dec:=json.NewDecoder(io.LimitReader(in,32<<20))
 dec.DisallowUnknownFields()
 var samples []qualification.Sample
 if err:=dec.Decode(&samples);err!=nil{return fmt.Errorf("decode corpus: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF {
  if err==nil{return errors.New("trailing JSON content")}
  return fmt.Errorf("trailing input: %w",err)
 }
 report,err:=qualification.Evaluate(samples,*threshold);if err!=nil{return err}
 enc:=json.NewEncoder(out);enc.SetIndent("","  ")
 return enc.Encode(report)
}
func main(){
 if err:=run(os.Args[1:],os.Stdin,os.Stdout);err!=nil{
  fmt.Fprintln(os.Stderr,"classifier evaluation:",strings.TrimSpace(err.Error()))
  os.Exit(1)
 }
}
